package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/atotto/clipboard" // OSに依存しないクリップボード操作のためのライブラリ
	"github.com/fatih/color"
)

// ドメインの入力履歴
const (
	historyFile = "domain_history.txt"
	maxHistory  = 8
)

// パッケージレベルで正規表現をコンパイル
var (
	// コメント行を検出する正規表現 (行頭が # または空白文字で始まる)
	commentRegex = regexp.MustCompile(`^#|\s`)

	// FQDN を検証する正規表現
	fqdnRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

func PrintHelp() {
	str := `## dnschecker for Value-domain
Value-domainの「簡易DNS設定」で設定した値が、
「DNSサーバーからルックアップした値」と同じかチェックします

使い方(1)
対話モードでドメイン名、ファイルの内容を標準入力から受け付けます

./dnschecker 


使い方(2) 
以下のように、ドメインとDNS設定が保存されたファイルを指定することもできます

./dnschecker <domain> <file>

使用例：
./dnschecker my-domain.com dns-mydomain.conf
`
	fmt.Println(str)
}

func TestA(lookupvalue string, confvalue string, domain string) (string, bool) {
	var out strings.Builder
	// 設定の書式
	// a * IP  <skipped already>
	// a @ IP
	// a subdomain IP

	flag := false

	// 入力値を整形
	if strings.HasPrefix(lookupvalue, "www.") {
		// -- www.サブドメインの特別なケース処理
		// SSL証明書作成のため、www.subdomain が設定されている場合がある
		// 例 : a www.subdomain 10.101.11.102
		// この場合、AjustHostnme() はFQDNなのかサブドメインかの判断が難しいため、
		// 先頭が www. だった場合は、subdomain + domain とする
		// www.your-domain.comの場合は、a www IP となるためこの処理は適用されない
		lookupvalue = lookupvalue + "." + domain
	} else {
		// 通常のケース
		lookupvalue = AdjustHostname(strings.TrimSuffix(lookupvalue, "."), domain)
	}

	// DNSルックアップを実行
	iprecords, err := net.LookupIP(lookupvalue)
	if err != nil {
		out.WriteString(color.RedString("Error\n"))
		out.WriteString(fmt.Sprintf("DNS lookup failed for A record: %v\n", err))
		out.WriteString("\n")
		return out.String(), false
	}

	// 結果を表示
	out.WriteString("Type   : a\n")
	out.WriteString(fmt.Sprintf("Name   : %s\n", lookupvalue))

	// 一致するIPアドレスを探す
	for _, ip := range iprecords {
		if ip.String() == confvalue {
			out.WriteString(fmt.Sprintf("Value  : %s\n", ip.String()))
			flag = true
		}
	}

	if flag {
		out.WriteString(color.GreenString("OK\n"))
	} else {
		out.WriteString(color.RedString("Error\n"))
	}
	out.WriteString("\n")

	return out.String(), flag
}

func TestCNAME(lookupvalue string, confvalue string, domain string) (string, bool) {
	var out strings.Builder
	// 設定の書式
	// cname host FQDN
	// cname *.subdomain FQDN. <skipped already>

	flag := false

	// 入力値を整形
	if strings.Contains(lookupvalue, domain) {
		// すでにドメインが含まれている場合
		lookupvalue = strings.TrimSuffix(lookupvalue, ".")
	} else {
		// ドメインが含まれていない場合
		lookupvalue = AdjustHostname(strings.TrimSuffix(lookupvalue, "."), domain)
	}

	// 設定値から末尾のドットを削除
	confvalue = strings.TrimSuffix(confvalue, ".")

	// DNSルックアップを実行
	cname, err := net.LookupCNAME(lookupvalue)
	if err != nil {
		out.WriteString(color.RedString("Error\n"))
		out.WriteString(fmt.Sprintf("DNS lookup failed for CNAME record: %v\n", err))
		out.WriteString("\n")
		return out.String(), false
	}

	// 結果を表示
	out.WriteString("Type   : cname\n")
	out.WriteString(fmt.Sprintf("Name   : %s\n", lookupvalue))

	// 一致するCNAMEレコードを確認
	if strings.Contains(cname, confvalue) {
		out.WriteString(fmt.Sprintf("Value  : %s\n", cname))
		flag = true
	}

	if flag {
		out.WriteString(color.GreenString("OK\n"))
	} else {
		out.WriteString(color.RedString("Error\n"))
	}
	out.WriteString("\n")

	return out.String(), flag
}

func TestMX(inputHost string, inputValue string, domain string, configParts []string) (string, bool) {
	var out strings.Builder
	// 設定の書式
	// mx @ smtp-server(.)
	// mx smtp-server(.) priority
	// mx host priority smtp-server(.)

	flag := false
	var lookupvalue string
	var confvalue string

	// MXレコードの設定パターンに基づいて入力値を処理
	if len(configParts) == 3 {
		if inputHost == "@" {
			// case : mx @ smtp-server(.)
			lookupvalue = domain
			confvalue = strings.TrimSuffix(inputValue, ".")
		} else {
			// case : mx smtp-server(.) priority
			lookupvalue = domain
			confvalue = strings.TrimSuffix(inputHost, ".")
		}
	} else if len(configParts) == 4 {
		// case : mx host priority smtp-server(.)
		lookupvalue = AdjustHostname(strings.TrimSuffix(configParts[3], "."), domain)
		confvalue = strings.TrimSuffix(inputHost, ".")
	}

	// DNSルックアップを実行
	mxrecords, err := net.LookupMX(lookupvalue)
	if err != nil {
		out.WriteString(color.RedString("Error\n"))
		out.WriteString(fmt.Sprintf("DNS lookup failed for MX record: %v\n", err))
		out.WriteString("\n")
		return out.String(), false
	}

	// 結果を表示
	out.WriteString("Type   : mx\n")
	out.WriteString(fmt.Sprintf("Name   : %s\n", lookupvalue))

	// 一致するMXレコードを探す
	for _, mx := range mxrecords {
		if strings.TrimSuffix(strings.ToLower(mx.Host), ".") == strings.ToLower(confvalue) {
			out.WriteString(fmt.Sprintf("Value  : %s\n", strings.TrimSuffix(mx.Host, ".")))
			flag = true
		}
	}

	if flag {
		out.WriteString(color.GreenString("OK\n"))
	} else {
		out.WriteString(color.RedString("Error\n"))
	}
	out.WriteString("\n")

	return out.String(), flag
}

func TestTXT(inputHost string, inputValue string, domain string, configParts []string) (string, bool) {
	var out strings.Builder
	// 設定の書式
	// txt @ v=spf1 array of values
	// txt @ IP
	// txt host(.) value
	// txt host(.) v=spf1 value
	// txt x._domainkey value
	// txt _dmarc(subdomain) value
	// txt value

	flag := false
	var lookupvalue string
	var confvalue string

	// TXTレコードの様々なパターンを処理
	if inputHost == "@" {
		if strings.Contains(inputValue, "v=spf1") {
			// case : txt @ v=spf1 value
			lookupvalue = AdjustHostname(inputHost, domain)

			// SPF値の場合は特別な処理：全ての値を結合して設定値とする
			confvalue = inputValue // まず最初の値を設定
			if 3 <= len(configParts) {
				for i := 3; i < len(configParts); i++ {
					confvalue += " " + configParts[i]
				}
			}
		} else {
			// case : txt @ IP
			lookupvalue = AdjustHostname(strings.TrimSuffix(inputHost, "."), domain)
			confvalue = inputValue
		}
	} else if strings.Contains(inputHost, domain) {
		// case : txt host(.) value
		lookupvalue = strings.TrimSuffix(inputHost, ".")
		confvalue = inputValue // 最初の値を設定
		if 3 <= len(configParts) {
			for i := 3; i < len(configParts); i++ {
				confvalue += " " + configParts[i]
			}
		}
	} else if strings.Contains(inputValue, "v=spf1") {
		// case : txt host(.) v=spf1 value
		if strings.Contains(inputHost, domain) {
			lookupvalue = strings.TrimSuffix(inputHost, ".")
		} else {
			lookupvalue = AdjustHostname(strings.TrimSuffix(inputHost, "."), domain)
		}
		confvalue = inputValue // 最初の値を設定
		if 3 <= len(configParts) {
			for i := 3; i < len(configParts); i++ {
				confvalue += " " + configParts[i]
			}
		}
	} else if strings.Contains(inputHost, "domainkey") {
		// case : txt x._domainkey value
		lookupvalue = AdjustHostname(strings.TrimSuffix(inputHost, "."), domain)
		confvalue = inputValue // 最初の値を設定
		if 3 <= len(configParts) {
			for i := 3; i < len(configParts); i++ {
				confvalue += " " + configParts[i]
			}
		}
	} else if strings.Contains(inputHost, "dmarc") {
		// case : txt _dmarc(subdomain) value
		lookupvalue = "_dmarc." + domain
		confvalue = inputValue // 最初の値を設定
		if 3 <= len(configParts) {
			for i := 3; i < len(configParts); i++ {
				confvalue += " " + configParts[i]
			}
		}
	} else {
		// case : txt value
		lookupvalue = AdjustHostname(inputHost, domain)
		confvalue = inputValue // 最初の値を設定
		if 3 <= len(configParts) {
			for i := 3; i < len(configParts); i++ {
				confvalue += " " + configParts[i]
			}
		}
	}

	// DNSルックアップを実行
	txtrecords, err := net.LookupTXT(lookupvalue)
	if err != nil {
		out.WriteString(color.RedString("Error\n"))
		out.WriteString(fmt.Sprintf("DNS lookup failed for TXT record: %v\n", err))
		out.WriteString("\n")
		return out.String(), false
	}

	// 結果を表示
	out.WriteString("Type   : txt\n")
	out.WriteString(fmt.Sprintf("Name   : %s\n", lookupvalue))

	// 一致するTXTレコードを探す
	for _, txt := range txtrecords {

		if txt == confvalue {
			out.WriteString(fmt.Sprintf("Value  : %s\n", txt))
			flag = true
		}
	}

	if flag {
		out.WriteString(color.GreenString("OK\n"))
	} else {
		out.WriteString(color.RedString("Error\n"))
	}
	out.WriteString("\n")

	return out.String(), flag
}

func TestNS(lookupvalue string, confvalue string, domain string) (string, bool) {
	var out strings.Builder
	// 設定の書式
	// ns subdomain host

	flag := false

	// 入力値を整形
	if strings.Contains(lookupvalue, domain) {
		// すでにドメインが含まれている場合はそのまま使用
		lookupvalue = strings.TrimSuffix(lookupvalue, ".")
	} else {
		// ドメインが含まれていない場合は適切に調整
		lookupvalue = AdjustHostname(strings.TrimSuffix(lookupvalue, "."), domain)
	}

	// 設定値から末尾のドットを削除
	confvalue = strings.TrimSuffix(confvalue, ".")

	// DNSルックアップを実行
	nameserver, err := net.LookupNS(lookupvalue)
	if err != nil {
		out.WriteString(color.RedString("Error\n"))
		out.WriteString(fmt.Sprintf("DNS lookup failed for NS record: %v\n", err))
		out.WriteString("\n")
		return out.String(), false
	}

	// 結果を表示
	out.WriteString("Type   : ns\n")
	out.WriteString(fmt.Sprintf("Name   : %s\n", lookupvalue))

	// 一致するNSレコードを探す
	for _, ns := range nameserver {
		if strings.Contains(ns.Host, confvalue) {
			out.WriteString(fmt.Sprintf("Value  : %s\n", ns.Host))
			flag = true
		}
	}

	if flag {
		out.WriteString(color.GreenString("OK\n"))
	} else {
		out.WriteString(color.RedString("Error\n"))
	}
	out.WriteString("\n")

	return out.String(), flag
}

func AdjustHostname(hostname string, domain string) string {
	// コンパイル済みの正規表現を使用
	match := fqdnRegex.MatchString(hostname)
	var fqdn string

	// Replace @ with domain
	if hostname == "@" {
		fqdn = domain
		/*} else if strings.Contains(hostname, domain) {
		  //fqdn = strings.TrimSuffix(fqdn, ".")
		  fqdn = hostname */
	} else if !match {
		fqdn = hostname + "." + domain
	} else {
		fqdn = hostname
	}

	return fqdn
}

func IfFileExist(fileName string) {
	_, error := os.Stat(fileName)

	// check if file exits
	if os.IsNotExist(error) {
		fmt.Printf("File not found : %v \n", fileName)
		PrintHelp()
		os.Exit(0)
	} /* else {
	        fmt.Printf("%v file exist\n", fileName)
	} */
}

// ドメイン入力履歴　ロード・保存・更新
func loadHistory() []string {
	file, err := os.Open(historyFile)
	if err != nil {
		return []string{}
	}
	defer file.Close()

	var history []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			history = append(history, line)
		}
	}
	return history
}

func saveHistory(history []string) {
	// 最大 maxHistory 件までに制限
	if len(history) > maxHistory {
		history = history[len(history)-maxHistory:]
	}
	file, err := os.Create(historyFile)
	if err != nil {
		return
	}
	defer file.Close()

	for _, line := range history {
		file.WriteString(line + "\n")
	}
}

func updateHistory(newDomain string) {
	history := loadHistory()

	// すでに存在するなら削除
	var updated []string
	for _, h := range history {
		if h != newDomain {
			updated = append(updated, h)
		}
	}
	updated = append(updated, newDomain)

	saveHistory(updated)
}

// DNSチェック処理を行う関数
func performDNSCheck(domain string, filename string, parallel bool) {
	// init default values
	count_ok := 0
	count_err := 0
	count_untested := 0

	// Open file
	fp, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error when opening file")
		return
	}
	defer fp.Close()

	// Read file
	scanner := bufio.NewScanner(fp)

	if parallel {
		var wg sync.WaitGroup
		var mu sync.Mutex

		for scanner.Scan() {
			line := scanner.Text()
			if len(line) == 0 {
				continue
			}
			wg.Add(1)
			go func(line string) {
				defer wg.Done()

				output, ok, untested := processLine(line, domain)
				if output == "" {
					return
				}

				mu.Lock()
				defer mu.Unlock()

				fmt.Print(output)
				// Explicitly flush stdout to ensure immediate output
				os.Stdout.Sync()

				if untested > 0 {
					count_untested += untested
				} else if ok {
					count_ok++
				} else {
					count_err++
				}
			}(line)
		}
		wg.Wait()
	} else {
		for scanner.Scan() {
			line := scanner.Text()
			if len(line) == 0 {
				continue
			}

			output, ok, untested := processLine(line, domain)
			if output == "" {
				continue
			}
			fmt.Print(output)

			if untested > 0 {
				count_untested += untested
			} else if ok {
				count_ok++
			} else {
				count_err++
			}
		}
	}

	if err = scanner.Err(); err != nil {
		fmt.Println("Error while reading file")
		return
	}

	fmt.Printf("-----------------\n")
	fmt.Printf("Summary \n")
	// OK
	green := color.New(color.FgGreen).PrintfFunc()
	green("OK       : %s\n", strconv.Itoa(count_ok))
	// Error
	red := color.New(color.FgRed).PrintfFunc()
	red("Error    : %s\n", strconv.Itoa(count_err))
	// Untested
	yellow := color.New(color.FgYellow).PrintfFunc()
	yellow("Untested : %s\n", strconv.Itoa(count_untested))
	fmt.Printf("-----------------\n")
}

// processLine processes a single line from the config file.
func processLine(line string, domain string) (output string, ok bool, untested int) {
	var out strings.Builder
	splittedLine := strings.Fields(line)

	// skip empty lines
	if len(splittedLine) == 0 {
		return "", false, 0
	}

	// Skip comment
	matched_comment := commentRegex.MatchString(splittedLine[0])
	if matched_comment {
		return "", false, 0 // empty output, not ok, no untested
	}

	// Print the config line
	out.WriteString("Config : ")
	out.WriteString(line)
	out.WriteString("\n")

	// Declare & set default values
	dnshost := ""

	// Untest */wildcard, otherwise check DNS values dpending on each type
	if len(splittedLine) > 1 && strings.Contains(splittedLine[1], "*") {
		out.WriteString(color.YellowString("Untested : * (wildcard) used, test manually\n"))
		out.WriteString("\n") // Empty line
		return out.String(), false, 1
	}

	var testOutput string
	var testOK bool

	switch splittedLine[0] {
	case "a":
		dnshost = splittedLine[1]
		confvalue := splittedLine[2]
		testOutput, testOK = TestA(dnshost, confvalue, domain)
		out.WriteString(testOutput)
		return out.String(), testOK, 0

	case "cname":
		dnshost = splittedLine[1]
		confvalue := splittedLine[2]
		testOutput, testOK = TestCNAME(dnshost, confvalue, domain)
		out.WriteString(testOutput)
		return out.String(), testOK, 0

	case "mx":
		testOutput, testOK = TestMX(splittedLine[1], splittedLine[2], domain, splittedLine)
		out.WriteString(testOutput)
		return out.String(), testOK, 0

	case "txt":
		testOutput, testOK = TestTXT(splittedLine[1], splittedLine[2], domain, splittedLine)
		out.WriteString(testOutput)
		return out.String(), testOK, 0

	case "ns":
		dnshost = strings.TrimSuffix(splittedLine[1], ".")
		confvalue := strings.TrimSuffix(splittedLine[2], ".")
		testOutput, testOK = TestNS(dnshost, confvalue, domain)
		out.WriteString(testOutput)
		return out.String(), testOK, 0

	case "svr", "caa", "alias", "aaaa":
		out.WriteString(color.YellowString(fmt.Sprintf("Untested : %s record not yet implemented\n", splittedLine[0])))
		out.WriteString("\n") // Empty line
		return out.String(), false, 1

	default:
		out.WriteString(color.YellowString("Untested : %s\n", splittedLine[0]))
		out.WriteString("\n") // Empty line
		return out.String(), false, 1
	}
}

// 対話モードでドメイン名とDNS設定を取得する関数
func getInputsInteractively() (string, string) {
	reader := bufio.NewReader(os.Stdin)

	// 履歴読み込み
	history := loadHistory()
	var domain string
	if len(history) > 0 {
		fmt.Println("最近使ったドメイン:")
		for i, h := range history {
			fmt.Printf("  %d: %s\n", i+1, h)
		}
		fmt.Print("番号を選ぶか、新しいドメインを入力してください: ")
	} else {
		fmt.Print("ドメイン名を入力してください (Enterで確定): ")
	}
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	choice, err := strconv.Atoi(input)
	if err == nil && choice >= 1 && choice <= len(history) {
		domain = history[choice-1]
	} else {
		domain = input
	}

	domain = strings.TrimSpace(domain)
	if domain == "" {
		fmt.Println("ドメインが空です")
		os.Exit(1)
	}

	// domain履歴に保存
	updateHistory(domain)

	// ここからはDNS設定取得
	var fileContent string

	fmt.Println("Value-domainのDNS設定を入力する方法を選択してください:")
	fmt.Println("1: 直接入力・貼り付け")
	fmt.Println("2: クリップボードからペースト")
	if runtime.GOOS == "darwin" {
		fmt.Printf("Macで1行の文字列が1024文字を超える場合、2を選んでください。\n")
	}

	var inputMethod string
	fmt.Print("選択 (1 または 2, デフォルトは 1): ")
	inputMethod, _ = reader.ReadString('\n')
	inputMethod = strings.TrimSpace(inputMethod)

	if inputMethod == "2" {
		// クリップボードからペースト
		fmt.Print("Value-domainのDNS設定をコピーしてください（クリップボードにコピーしてください）:\n")
		fmt.Print("クリップボードにコピーされたら、自動的にDNS設定チェックが実行されます\n")

		// クリップボードを空にする
		err := clipboard.WriteAll("")
		if err != nil {
			fmt.Println("クリップボードのクリアに失敗しました:", err)
		} else {
			//fmt.Println("クリップボードを空にしました")
		}

		// クリップボードにDNS設定がコピーされたら取得
		var previousContent string
		var firstCheck = true

		for {
			currentContent, err := clipboard.ReadAll()
			if err != nil {
				fmt.Println("クリップボード読み取り中にエラーが発生しました:", err)
				fmt.Print(".")
				time.Sleep(1 * time.Second)
				continue
			}

			// 初回は前回の内容を記録するだけ
			if firstCheck {
				previousContent = currentContent
				firstCheck = false
			} else if currentContent != previousContent && len(currentContent) > 0 {
				// 内容が変わっていて、空でなければ処理を実行
				fileContent = currentContent
				break
			}

			previousContent = currentContent
			fmt.Print(".")
			time.Sleep(1 * time.Second)
		}
		fmt.Println() // 改行
	} else {
		// デフォルトは手動入力
		fmt.Print("Value-domainのDNS設定を貼り付けてください（Enterでチェックを実行）:\n")
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				break // 空行で入力終了
			}
			fileContent += line + "\n"
		}

		if err := scanner.Err(); err != nil {
			fmt.Println("標準入力からの読み込み中にエラーが発生しました:", err)
			os.Exit(1)
		}
	}

	// ファイルの内容を一時ファイルに書き込む
	tmpfile, err := os.CreateTemp("", "dns-config-*.conf")
	if err != nil {
		log.Fatal(err)
	}

	filename := tmpfile.Name()

	if _, err := tmpfile.Write([]byte(fileContent)); err != nil {
		log.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	return domain, filename
}

// ユーザーに再実行するか確認する関数
func askForRerun() bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nもう一度実行しますか？ (Y/n): ")
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))

	// デフォルトはYes（何も入力されない場合やYが入力された場合）
	return answer == "" || answer == "y" || answer == "yes"
}

func main() {
	// コマンドライン引数のチェック
	originalArgs := os.Args
	var filename, domain string
	var tmpFiles []string // 一時ファイルのリストを保持

	parallel := false
	processedArgs := []string{originalArgs[0]}
	for _, arg := range originalArgs[1:] {
		if arg == "-p" {
			parallel = true
		} else {
			processedArgs = append(processedArgs, arg)
		}
	}

	args := processedArgs
	isInteractive := false // Flag to track interactive mode

	for {
		if len(args) < 2 {
			isInteractive = true // Set flag for interactive mode
			// 対話モードでドメイン名とファイルの内容を取得
			domain, filename = getInputsInteractively()
			tmpFiles = append(tmpFiles, filename) // 一時ファイルを記録
		} else if len(args) == 2 {
			PrintHelp()
			os.Exit(0)
		} else if len(args) > 3 {
			fmt.Printf("Too many arguments\n\n")
			PrintHelp()
			os.Exit(0)
		} else {
			isInteractive = false // Not interactive mode
			IfFileExist(args[2]) // ファイルがあることを確認
			domain = args[1]
			filename = args[2]
		}

		// DNSチェックを実行
		performDNSCheck(domain, filename, parallel)

		// Only ask for rerun if in interactive mode
		if isInteractive {
			if !askForRerun() {
				break // 再実行しない場合はループを抜ける
			}
		} else {
			// In non-interactive mode, we don't ask for rerun, so break after one execution
			break
		}

		// コマンドライン引数を使っていた場合は、対話モードに切り替える
		if len(originalArgs) > 1 {
			args = []string{originalArgs[0]} // プログラム名だけ残す
		}
	}

	// 一時ファイルを削除
	for _, file := range tmpFiles {
		os.Remove(file)
	}
}