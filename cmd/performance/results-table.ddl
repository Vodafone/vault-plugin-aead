CREATE TABLE `vf-pf1-ca-live.aead_tests.results_new`
(
  RunStartDateTime DATETIME,
  RunEndDateTime DATETIME,
  TotalMilliseconds INT64,
  RateAeadOpsPerSec FLOAT64,
  ClientIterations INT64,
  ClientConcurrency INT64,
  DatasetRows INT64,
  DatasetFields INT64,
  TotalHTTPCalls INT64,
  TotalAeadOperations INT64,
  VaultPodMaxCpuPcnt FLOAT64,
  VaultPodMaxMemPcnt FLOAT64,
  VaultPodAvgCpuPcnt FLOAT64,
  VaultPodAvgMemPcnt FLOAT64,
  VaultPluginVersion STRING,
  VaultPodImage STRING,
  VaultPodCount INT64,
  VaultPodCpu INT64,
  VaultPodMem INT64,
  VaultURL STRING,
  ClientHost STRING,
  ClientTotalMemory INT64,
  ClientCPUCount INT64,
  ClientCPUCores INT64,
  ClientCPUModel STRING,
  ClientBatchMode BOOL,
  ClientRepeat INT64,
  TestResult STRING,
  ClientBatchColumnMode BOOL
);