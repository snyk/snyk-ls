package main

import (
    "fmt"
    "runtime"
)

// Function to convert bytes to megabytes
func bytesToMB(bytes uint64) float64 {
    return float64(bytes) / (1024 * 1024)
}

// Function to print memory statistics
func printMemoryStats() {
    var memStats runtime.MemStats
    runtime.ReadMemStats(&memStats)

    fmt.Printf("Allocated Memory (MB): %.2f\n", bytesToMB(memStats.Alloc))
    fmt.Printf("Heap Allocated Memory (MB): %.2f\n", bytesToMB(memStats.HeapAlloc))
    fmt.Printf("Total Allocated Memory (MB): %.2f\n", bytesToMB(memStats.TotalAlloc))
    fmt.Printf("System Memory (MB): %.2f\n", bytesToMB(memStats.Sys))
    fmt.Printf("Number of Garbage Collections: %d\n", memStats.NumGC)
}

func main() {
    printMemoryStats()
}

