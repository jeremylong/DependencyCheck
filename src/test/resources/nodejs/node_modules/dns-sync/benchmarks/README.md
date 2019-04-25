### how to

cd benchmarks
npm install
node perf.js


### Perf report

***Node@v0.12.0***

 **With shelljs - ~0.3.0**

```
 success case x 8.20 ops/sec ±1.32% (25 runs sampled)
 failure case x 8.21 ops/sec ±1.59% (25 runs sampled)

 34% CPU and ≈66MB memory footprint
```

**With shelljs - ~0.4.0**

```
 success case x 9.37 ops/sec ±1.42% (28 runs sampled)
 failure case x 9.39 ops/sec ±1.42% (28 runs sampled)

  2% CPU and ≈20MB memory footprint
```