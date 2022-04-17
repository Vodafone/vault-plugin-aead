package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/bigquery"
	"cloud.google.com/go/civil"
	lorem "github.com/bozaro/golorem"
	backoff "github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	metrics "k8s.io/metrics/pkg/client/clientset/versioned"
)

// type Payload struct {
// 	Field1 string `json:"field1"`
// 	Field2 string `json:"field2"`
// }
type Options struct {
	rowNumber     int
	token         string
	url           string
	fieldNumber   int
	concurrency   int
	batchMode     bool
	repeat        int
	saveResults   bool
	httpProxy     string
	debug         bool
	baseFieldName string
	waitUntil     string
	columnBased   bool
	kubeStats     bool
}

type Results struct {
	RunStartDateTime      civil.DateTime
	RunEndDateTime        civil.DateTime
	TotalMilliseconds     int64
	RateAeadOpsPerSec     float64
	ClientIterations      int
	ClientConcurrency     int
	DatasetRows           int
	DatasetFields         int
	TotalHTTPCalls        int64
	TotalAeadOperations   int64
	VaultPodMaxCpuPcnt    float64
	VaultPodMaxMemPcnt    float64
	VaultPodAvgCpuPcnt    float64
	VaultPodAvgMemPcnt    float64
	VaultPluginVersion    string
	VaultPodImage         string
	VaultPodCount         int
	VaultPodCpu           int64
	VaultPodMem           int64
	VaultURL              string
	ClientHost            string
	ClientTotalMemory     int64
	ClientCPUCount        int
	ClientCPUCores        int
	ClientCPUModel        string
	ClientBatchMode       bool
	ClientRepeat          int
	TestResult            string
	ClientBatchColumnMode bool
}

type K8sResults struct {
	VaultPodMaxCpuPcnt float64
	VaultPodMaxMemPcnt float64
	VaultPodAvgCpuPcnt float64
	VaultPodAvgMemPcnt float64
	VaultPluginVersion string
	VaultPodImage      string
	VaultPodCount      int
	VaultPodCpu        int64
	VaultPodMem        int64
}

type K8SRunningTotals struct {
	count                   int
	cpuRunningTotalUsedPcnt float64
	memRunningTotalUsedPcnt float64
}

/*
./performance -f 6 -r 1000 -c 1 -i 1 -t <token> -u <url> -b -d -s
*/

func main() {

	var options Options
	var results Results

	token := flag.String("t", "", "token for vault access")
	url := flag.String("u", "http://127.0.0.1:8080", "url for vault access")
	fieldNumber := flag.Int("f", 1, "number of fields per row")
	rowNumber := flag.Int("r", 1, "number of rows per dataset")
	concurrency := flag.Int("c", 1, "number of concurrent clients")
	repeat := flag.Int("i", 1, "number of iterations")
	batchMode := flag.Bool("b", false, "send all data as 1 batch (32Mb json limit)")
	saveresults := flag.Bool("s", false, "save results to bq vf-pf1-ca-live.aead_tests.results")
	httpProxy := flag.String("p", "", "proxy url - something like http://a-real-proxy.vodafone.com:8080")
	debug := flag.Bool("d", false, "debug")
	baseFieldName := flag.String("n", "field", "root name for fields to be anonynised - default field so names would be field0, field1, field2.....fieldn")
	waitUntil := flag.String("w", "", "UTC datetime in the format of 2022-03-28 11:05 YYYY-MM-DD HH24:MM to delay until")
	columnBased := flag.Bool("col", false, "column based ops (only if batchMode = true)")
	kubeStats := flag.Bool("k", false, "collect kube stat averages")

	flag.Parse()
	options.fieldNumber = *fieldNumber
	options.rowNumber = *rowNumber
	options.concurrency = *concurrency
	options.repeat = *repeat
	options.batchMode = *batchMode
	options.saveResults = *saveresults
	options.token = *token
	options.url = *url
	options.httpProxy = *httpProxy
	options.debug = *debug
	options.baseFieldName = *baseFieldName
	options.waitUntil = *waitUntil
	options.columnBased = *columnBased
	options.kubeStats = *kubeStats

	doWaitIfRequired(options)

	t := time.Now().UTC()
	results.RunStartDateTime = civil.DateTimeOf(t)

	fmt.Printf("START: ROWS=%v FIELDS=%v BATCH=%v CONCURRENCY=%v REPEAT=%v SAVE_RESULTS=%v COLUMN_BASED=%v\n",
		options.rowNumber,
		options.fieldNumber,
		options.batchMode,
		options.concurrency,
		options.repeat,
		options.saveResults,
		options.columnBased)

	ch_quit := make(chan bool)
	ch_results := make(chan K8sResults)

	var k8sDets K8sResults
	if options.saveResults {
		if options.kubeStats {
			getPodStats(ch_quit, ch_results)
		} else {
			getPodSetup(&k8sDets)
		}
	}

	channel := make(chan bool, options.concurrency)
	for j := 0; j < options.repeat; j++ {
		fmt.Printf("ITERATION=%v\n", j)
		for i := 0; i < options.concurrency; i++ {
			// initialise the concurrent goroutine
			if !options.batchMode {
				go gotest(&options, channel)
			} else {
				go gotestBulk(&options, channel)
			}
		}

		success := true
		for i := 0; i < options.concurrency; i++ {
			// collect and throw away the 'done' marker from the channel
			ch_success := <-channel
			if !ch_success {
				success = false
			}
		}
		if success {
			results.TestResult = "PASS"
		} else {
			results.TestResult = "FAIL"
		}
	}
	tend := time.Now().UTC()
	results.RunEndDateTime = civil.DateTimeOf(tend)

	ts := time.Since(t)
	results.TotalMilliseconds = ts.Milliseconds()

	if options.kubeStats {
		k8sDets = <-ch_results
		close(ch_quit)
	}

	if options.saveResults {
		saveResults(options, results, k8sDets)
	}

	fmt.Printf("%v END PARALLELISATION\n", ts)
}

func doWaitIfRequired(options Options) {

	if options.waitUntil != "" {
		startDate, err := time.Parse("2006-01-02 15:04", options.waitUntil)
		if err != nil {
			panic(err)
		}

		fmt.Printf("StartDateTime UTC:=%v\n", startDate.UTC())
		tn := time.Now().UTC()
		fmt.Printf("Now UTC:=%v\n", tn)

		secToWait := startDate.Sub(tn).Seconds()

		if secToWait < 0 {
			return
		}
		fmt.Printf("Sleeping for %v seconds until %v\n", secToWait, startDate.UTC())
		time.Sleep(startDate.Sub(tn))
		fmt.Printf("Waking Up")
	}
}

func gotestBulk(options *Options, ch chan bool) {

	// client := createHttpClient(options)

	var originalDataMap = map[int]map[string]interface{}{}
	var bulkDecryptedDataMap = map[int]map[string]interface{}{}

	// var encryptedBulkMap = map[string]interface{}{}
	var decryptedBulkMap = map[string]interface{}{}

	t := time.Now()
	fmt.Printf("START MAKE MAP %v ROWS of %v FIELDS EACH\n", options.rowNumber, options.fieldNumber)

	makeRandomData(originalDataMap, options)

	fmt.Printf("%v FINISH MAKE MAP %v ROWS\n", time.Since(t), len(originalDataMap))

	// bs, _ := json.Marshal(inputMap)
	// fmt.Printf("Length=%v", bs)

	// err := os.WriteFile("perfdata.json", bs, 0644)
	// check(err)

	// fmt.Printf("Length=%v", len(inputMap))

	t = time.Now()
	if options.debug {
		fmt.Println("INPUT MAP=", originalDataMap)
	}
	// what a pain - even though it looks the same we need to convert
	// map[int]map[string]interface{}{}
	// to
	// map[string]interface{}{}
	bulkInputMap := make(map[string]interface{})
	for k, v := range originalDataMap {
		bulkInputMap[strconv.Itoa(k)] = v
	}

	// if options.debug {
	// 	fmt.Println("BULK MAP=", bulkInputMap)
	// }
	url := ""
	if options.columnBased && options.batchMode {
		fmt.Println("COLUMN BASED BULK ENCRYPT")
		url = options.url + "/v1/aead-secrets/encryptcol"
	} else {
		url = options.url + "/v1/aead-secrets/encrypt"
	}
	encryptedBulkMap, err := encryptOrDecryptData(url, bulkInputMap, options)
	if err != nil {
		panic(err)
	}
	// fmt.Println("ENCRYPTED BULK MAP=", encryptedBulkMap)

	if options.debug {
		fmt.Println("ENCRYPTED MAP=", encryptedBulkMap)
	}
	fmt.Printf("%v FINISH BULK ENCRYPT, START DECRYPT\n", time.Since(t))

	t = time.Now()

	if options.columnBased && options.batchMode {
		fmt.Println("COLUMN BASED BULK DECRYPT")
		url = options.url + "/v1/aead-secrets/decryptcol"
	} else {
		url = options.url + "/v1/aead-secrets/decrypt"
	}
	decryptedBulkMap, err = encryptOrDecryptData(url, encryptedBulkMap, options)
	if err != nil {
		panic(err)
	}
	if options.debug {
		fmt.Println("DECRYPTED BULK MAP=", decryptedBulkMap)
	}

	fmt.Printf("%v FINISH BULK DECRYPT\n", time.Since(t))

	for k, v := range decryptedBulkMap {

		// convert the value into a map
		m, ok := v.(map[string]interface{})
		if !ok {
			panic("expecting a map")
		}
		i, _ := strconv.Atoi(k)
		bulkDecryptedDataMap[i] = m
	}

	success := true
	t = time.Now()
	if !reflect.DeepEqual(originalDataMap, bulkDecryptedDataMap) {
		success = false
		fmt.Printf("\ndata is not the same \nORIG=%v \nDECRYPTED=%v", originalDataMap, bulkDecryptedDataMap)
	} else {
		if options.debug {
			fmt.Printf("\ndata is the same \nORIG=%v \nDECRYPTED=%v", originalDataMap, bulkDecryptedDataMap)
		}
	}

	fmt.Printf("%v FINISH COMPARISON\n", time.Since(t))

	ch <- success
}

func createHttpClient(options *Options) *retryablehttp.Client {
	var tr *http.Transport
	if options.httpProxy == "" {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		proxyUrl, _ := url.Parse(options.httpProxy)
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(proxyUrl),
		}
	}

	// Hmmm dodgy
	httpClient := &http.Client{Transport: tr}
	client := retryablehttp.NewClient()
	client.HTTPClient = httpClient
	return client
}

func gotest(options *Options, ch chan bool) {

	//  client := createHttpClient(options)

	var err error
	var originalDataMap = map[int]map[string]interface{}{}

	var encryptedMap = map[int]map[string]interface{}{}
	var encryptedRowMap = map[string]interface{}{}

	var decryptedMap = map[int]map[string]interface{}{}
	var decryptedRowMap = map[string]interface{}{}

	t := time.Now()
	fmt.Printf("START MAKE MAP %v ROWS of %v FIELDS EACH\n", options.rowNumber, options.fieldNumber)

	makeRandomData(originalDataMap, options)

	fmt.Printf("%v FINISH MAKE MAP %v ROWS\n", time.Since(t), len(originalDataMap))
	if options.debug {
		fmt.Println("INPUT MAP=", originalDataMap)
	}

	// bs, _ := json.Marshal(inputMap)
	// fmt.Printf("Length=%v", bs)

	// err := os.WriteFile("perfdata.json", bs, 0644)
	// check(err)

	// fmt.Printf("Length=%v", len(inputMap))

	fmt.Printf("%v START ENCRYPT\n", time.Since(t))

	t = time.Now()
	for k, v := range originalDataMap {
		// send each row, one at a time as map[string]interface{}
		// fmt.Printf("Key=%v Value=%v", k, v)
		url := options.url + "/v1/aead-secrets/encrypt"
		encryptedRowMap, err = encryptOrDecryptData(url, v, options)
		if err != nil {
			panic(err)
		}
		encryptedMap[k] = encryptedRowMap
	}
	fmt.Printf("%v FINISH ENCRYPT, START DECRYPT\n", time.Since(t))

	if options.debug {
		fmt.Println("ENCRYPTED MAP=", encryptedMap)
	}
	t = time.Now()

	for k, v := range encryptedMap {
		// fmt.Printf("Key=%v Value=%v", k, v)
		url := options.url + "/v1/aead-secrets/decrypt"
		decryptedRowMap, err = encryptOrDecryptData(url, v, options)
		if err != nil {
			panic(err)
		}
		decryptedMap[k] = decryptedRowMap
	}

	fmt.Printf("%v FINISH DECRYPT\n", time.Since(t))
	if options.debug {
		fmt.Println("DECRYPTED MAP=", decryptedMap)
	}
	t = time.Now()

	success := true
	if !reflect.DeepEqual(originalDataMap, decryptedMap) {
		success = false
		fmt.Printf("\ndata is not the same \nORIG=%v \nDECRYPTED=%v", originalDataMap, decryptedMap)
	} else {
		if options.debug {
			fmt.Printf("\ndata is the same \nORIG=%v \nDECRYPTED=%v", originalDataMap, decryptedMap)
		}
	}

	fmt.Printf("%v FINISH COMPARISON\n", time.Since(t))

	ch <- success
}

// func decryptData(inputMap map[string]interface{}, options *Options) map[string]interface{} {

// 	url := options.url + "/v1/aead-secrets/decrypt"

// 	respDecrypted := make(map[string]interface{})

// 	goDoHttp(inputMap, url, respDecrypted, options)

// 	dataDecrypted := respDecrypted["data"].(map[string]interface{})

// 	return dataDecrypted
// }

func encryptOrDecryptData(url string, inputMap map[string]interface{}, options *Options) (map[string]interface{}, error) {

	response := make(map[string]interface{})
	emptyMap := make(map[string]interface{})
	data := make(map[string]interface{})
	ok := true
	i := 0

	// I absolutely hate that you can only wrap a function with no args that returns an error "func() error" here
	// so I have to rely on variable scope, but life is too short
	operation := func() error {
		// if i > 0 {
		// 	fmt.Printf("Retry=%v encryptOrDecryptData\n", i)
		// }
		i++
		err := goDoHttp(inputMap, url, response, options)
		if err != nil {
			fmt.Printf("Try=%v Error after goDoHttp=%v\n", i, err)
			return err
		}
		data, ok = response["data"].(map[string]interface{})
		if !ok {
			errors, ok := response["errors"].([]interface{})
			if ok {
				// we have errors from vault
				fmt.Printf("Try=%v Vault Response=%v\n", i, errors)
				return fmt.Errorf("error response from vault %v", errors)
			} else {
				// we have errors but no idea why
				fmt.Printf("Try=%v Vault Response - no idea\n", i)
				return fmt.Errorf("error converting response to map[string]interface{}")
			}
		}
		return nil // or an error
	}
	xbo := backoff.NewExponentialBackOff()
	xbo.MaxElapsedTime = 1 * time.Minute
	err := backoff.Retry(operation, xbo)
	if err != nil {
		// Handle error.
		return emptyMap, err
	}

	return data, nil
}

func makeRandomData(inputMap map[int]map[string]interface{}, options *Options) {

	// fmt.Println("Options:", options)

	for i := 0; i < options.rowNumber; i++ {
		inputMap[i] = map[string]interface{}{}

		for j := 0; j < options.fieldNumber; j++ {
			randomStr := ""
			randomInt := rand.Intn(6)
			switch randomInt {
			case 0:
				randomStr = lorem.New().Email()
			case 1:
				randomStr = lorem.New().FirstName(lorem.Female)
			case 2:
				randomStr = lorem.New().FullName(lorem.Male)
			case 3:
				randomStr = lorem.New().Host()
			case 4:
				randomStr = lorem.New().Url()
			case 5:
				randomStr = lorem.New().Word(0, 10)
			default:
				randomStr = lorem.New().Word(0, 10)
			}

			inputMap[i][options.baseFieldName+fmt.Sprint(j)] = randomStr

		}
	}
}

func goDoHttp(inputData map[string]interface{}, url string, bodyMap map[string]interface{}, options *Options) error {

	client := createHttpClient(options)

	payloadBytes, err := json.Marshal(inputData)
	if err != nil {
		fmt.Printf("json.Marshal Error=%v", err)
		return err
	}
	inputBody := bytes.NewReader(payloadBytes)

	req, err := retryablehttp.NewRequest("POST", url, inputBody)
	if err != nil {
		fmt.Printf("http.NewRequest Error=%v", err)
		return err
	}
	req.Header.Set("X-Vault-Token", options.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("client.Do Error=%v", err)
		return err
	}

	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	err = json.Unmarshal([]byte(body), &bodyMap)
	if err != nil {
		fmt.Printf("Unmarshall Error=%v", err)
		return err
	}
	return nil
}

func goGetConfig(options *Options) {
	// Generated by curl-to-Go: https://mholt.github.io/curl-to-go

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", options.url+"/v1/aead-secrets/config", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", options.token)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body1, _ := io.ReadAll(resp.Body)

	var data1 map[string]interface{}
	err1 := json.Unmarshal([]byte(body1), &data1)
	if err1 != nil {
		panic(err1)
	}

	fmt.Printf("\n%s\n", data1)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func saveResults(options Options, results Results, k8sres K8sResults) {

	fillHostDetails(&results)

	results.VaultURL = options.url
	results.DatasetRows = options.rowNumber
	results.DatasetFields = options.fieldNumber
	results.ClientConcurrency = options.concurrency
	results.ClientBatchMode = options.batchMode
	results.ClientRepeat = options.repeat
	results.ClientIterations = options.repeat
	results.ClientBatchColumnMode = options.columnBased

	if options.batchMode {
		results.TotalHTTPCalls = int64(options.concurrency) * int64(options.repeat) * 2
	} else {
		results.TotalHTTPCalls = int64(options.concurrency) * int64(options.repeat) * int64(options.rowNumber) * 2
	}
	results.TotalAeadOperations = int64(options.concurrency) * int64(options.repeat) * int64(options.rowNumber) * 2 * int64(options.fieldNumber)
	results.RateAeadOpsPerSec = float64(results.TotalAeadOperations) / (float64(results.TotalMilliseconds) / 1000.0)

	results.VaultPluginVersion = k8sres.VaultPluginVersion
	results.VaultPodAvgCpuPcnt = k8sres.VaultPodAvgCpuPcnt
	results.VaultPodAvgMemPcnt = k8sres.VaultPodAvgMemPcnt
	results.VaultPodCount = k8sres.VaultPodCount
	results.VaultPodCpu = k8sres.VaultPodCpu
	results.VaultPodImage = k8sres.VaultPodImage
	results.VaultPodMaxCpuPcnt = k8sres.VaultPodMaxCpuPcnt
	results.VaultPodMaxMemPcnt = k8sres.VaultPodMaxMemPcnt
	results.VaultPodMem = k8sres.VaultPodMem

	ctx := context.Background()
	client, err := bigquery.NewClient(ctx, "vf-pf1-ca-live")
	if err != nil {
		log.Fatal(err)
	}
	myDataset := client.Dataset("aead_tests")
	table := myDataset.Table("results_new")
	u := table.Inserter()

	if err := u.Put(ctx, results); err != nil {
		log.Fatal(err)
	}
}

func fillHostDetails(results *Results) {
	v, _ := mem.VirtualMemory()

	cpuInfos, _ := cpu.Info()

	i := 0
	var cores int32
	cores = 0
	modelname := ""
	for _, ci := range cpuInfos {
		i++
		cores = ci.Cores
		modelname = ci.ModelName
		//fmt.Println(ci)
	}

	hi, _ := host.Info()

	results.ClientCPUCores = int(cores)
	results.ClientCPUCount = i
	results.ClientCPUModel = modelname
	results.ClientHost = hi.Hostname
	results.ClientTotalMemory = int64(v.Total)

	// fmt.Printf("ClientHost=%v ClientTotalMemory=%v ClientCPUCount=%v ClientCPUCores=%v ClientCPUModel=%v", hi.Hostname, v.Total, i, cores, modelname)
}

func getPodStats(quit chan bool, results chan K8sResults) {
	go func() {
		var res K8sResults
		kc, mc := getK8SClientsets()
		getK8SVaultLimits(kc, &res)
		var rtot K8SRunningTotals
		for {
			inspectK8s(mc, &res, &rtot)
			select {
			case <-quit:
				fmt.Println("stopping")
				return
			case results <- res:
			default:
			}
		}
	}()
}

func getPodSetup(res *K8sResults) {
	kc, _ := getK8SClientsets()
	getK8SVaultLimits(kc, res)
}

func inspectK8s(mc *metrics.Clientset, res *K8sResults, rtot *K8SRunningTotals) {

	podMetrics, err := mc.MetricsV1beta1().PodMetricses("vault-enterprise-ready").List(context.TODO(), metav1.ListOptions{})

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	for _, podMetric := range podMetrics.Items {
		podContainers := podMetric.Containers
		for _, container := range podContainers {
			memUsedQuantity, ok := container.Usage.Memory().AsInt64()
			if !ok {
				return
			}

			cpuUsedFloat := container.Usage.Cpu().AsApproximateFloat64()
			cpuUsedPcnt := cpuUsedFloat / float64(res.VaultPodCpu) * 100
			memUsedPcnt := float64(memUsedQuantity) / float64(res.VaultPodMem) * 100

			// set the max
			if cpuUsedPcnt > res.VaultPodMaxCpuPcnt {
				res.VaultPodMaxCpuPcnt = cpuUsedPcnt
			}
			if memUsedPcnt > res.VaultPodMaxMemPcnt {
				res.VaultPodMaxMemPcnt = memUsedPcnt
			}

			// work out the running totals
			rtot.count = rtot.count + 1
			rtot.cpuRunningTotalUsedPcnt = rtot.cpuRunningTotalUsedPcnt + cpuUsedPcnt
			rtot.memRunningTotalUsedPcnt = rtot.memRunningTotalUsedPcnt + memUsedPcnt

			// work out the averages
			res.VaultPodAvgCpuPcnt = rtot.cpuRunningTotalUsedPcnt / float64(rtot.count)
			res.VaultPodAvgMemPcnt = rtot.memRunningTotalUsedPcnt / float64(rtot.count)

			msg1 := fmt.Sprintf("Container Name: %s  CPU Pcnt: %v MEM Pcnt: %v CPU usage: %v  Memory usage: %d", container.Name, cpuUsedPcnt, memUsedPcnt, cpuUsedFloat, memUsedQuantity)
			fmt.Println(msg1)
			msg2 := fmt.Sprintf("Container Name: %s  MAX CPU Pcnt: %v AVG CPU Pcnt: %v MAX MEM usage: %v AVG MEM usage: %v", container.Name, res.VaultPodMaxCpuPcnt, res.VaultPodAvgCpuPcnt, res.VaultPodMaxMemPcnt, res.VaultPodAvgMemPcnt)
			fmt.Println(msg2)

		}

	}

	time.Sleep(15 * time.Second)
}

func getK8SClientsets() (*kubernetes.Clientset, *metrics.Clientset) {

	// https://github.com/kubernetes/client-go/tree/master/examples/out-of-cluster-client-configuration
	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	// https://stackoverflow.com/questions/52763291/get-current-resource-usage-of-a-pod-in-kubernetes-with-go-client
	mc, err := metrics.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	return clientset, mc
}

func getK8SVaultLimits(kc *kubernetes.Clientset, res *K8sResults) {
	// Examples for error handling:
	// - Use helper functions like e.g. errors.IsNotFound()
	// - And/or cast to StatusError and use its properties like e.g. ErrStatus.Message

	namespace := "vault-enterprise-ready"
	pl, _ := kc.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})

	res.VaultPodCount = len(pl.Items)
	for _, pod := range pl.Items {
		spec := pod.Spec
		for _, container := range spec.Containers {
			res.VaultPodCpu, _ = container.Resources.Limits.Cpu().AsInt64()
			res.VaultPodMem, _ = container.Resources.Limits.Memory().AsInt64()
			res.VaultPodImage = container.Image
			pos := strings.IndexAny(container.Image, "v0") // v position
			res.VaultPluginVersion = container.Image[pos:]
			break
		}
		break
	}
	fmt.Printf("VaultImage=%s, VaultPodCounter=%v VaultPodCpu=%v VaultPodMem=%v\n", res.VaultPodImage, len(pl.Items), res.VaultPodCpu, res.VaultPodMem)
}
