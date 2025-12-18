# Evaluation
We provide code snippets to perform 2 types of evaluations:
1. Standardized Benchmarks (SPEC + Browserbench Speedometer)
2. Microbenchmarks

This allows to us to calculate the overhead observed while running real-world applications and detecting true positive examples.

## Execution Order
1. The benchmark (in directory: `browserbench`, `microbenchmark`, and `spec` ) is run with the help of respective bash scripts and raw data is collected in respective `result(s)` directory or logging the STDOUT.
2. The raw data is filtered (with scripts in `filtering` directory) to collect data points (in `data`).
3. Result tables are finally generated (with scripts in `output` directory) using collected data points.

## Tables
In order to provide estimate for average overhead, we run evaluation on representative machines.
SPEC benchmark (00-17) along with microbenchmarks is run on an independent Fedora Linux 39 Server VM with 4 vCores and 24 GiB RAM on an Intel Xeon Gold 6248R CPU.
Browserbench Speedometer is run on Lenovo ThinkPad X1 Carbon Gen 10 with Intel Core i7-1260P CPU and 32 GiB RAM.

### Representative Tables
We provide raw data points collected during our evaluation in `data` directory.
Therefore, scripts available in `output` directory can be used to print tables provided in the paper and additional statistics.