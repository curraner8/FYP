package main

// returns true if the actual grade is worse than the threshold grade

func shouldFail(actual, threshold string) bool {
	order := map[string]int{"A": 6, "B": 5, "C": 4, "D": 3, "E": 2, "F": 1, "": 0}
	return order[actual] < order[threshold]
}
