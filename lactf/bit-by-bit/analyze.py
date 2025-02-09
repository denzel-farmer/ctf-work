#!/usr/bin/env python3
import numpy as np
import matplotlib.pyplot as plt

def load_sequence(filename):
    """Load a sequence of integers from a text file."""
    try:
        # Each line is assumed to contain one integer.
        return np.loadtxt(filename, dtype=int)
    except Exception as e:
        print(f"Error loading sequence from {filename}: {e}")
        return None

def plot_sequence(numbers):
    indices = np.arange(len(numbers))
    
    plt.figure(figsize=(12, 4))
    plt.plot(indices, numbers, marker='o', linestyle='-', markersize=3)
    plt.title("Sequence from sequence.txt")
    plt.xlabel("Index")
    plt.ylabel("Value")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("sequence_plot.png")
    plt.close()

def plot_differences(numbers):
    diffs = np.diff(numbers)
    plt.figure(figsize=(12, 4))
    plt.plot(diffs, marker='o', linestyle='-', markersize=3)
    plt.title("Differences Between Consecutive Values")
    plt.xlabel("Index")
    plt.ylabel("Difference")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("differences_plot.png")
    plt.close()
    return diffs

def autocorrelation(x):
    n = len(x)
    x = x - np.mean(x)
    result = np.correlate(x, x, mode='full')[-n:]
    # Normalize: each lag gets divided by the number of terms contributing
    result /= np.arange(n, 0, -1)
    return result

def plot_autocorrelation(numbers):
    ac = autocorrelation(numbers)
    plt.figure(figsize=(12, 4))
    plt.plot(ac, marker='o', linestyle='-', markersize=3)
    plt.title("Autocorrelation of the Sequence")
    plt.xlabel("Lag")
    plt.ylabel("Autocorrelation")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("autocorrelation_plot.png")
    plt.close()

def plot_scatter(numbers):
    # Scatter plot of current vs. next value
    x = numbers[:-1]
    y = numbers[1:]
    plt.figure(figsize=(6, 6))
    plt.scatter(x, y, s=10, alpha=0.5)
    plt.title("Scatter Plot: x[i] vs x[i+1]")
    plt.xlabel("x[i]")
    plt.ylabel("x[i+1]")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("scatter_plot.png")
    plt.close()

def main():
    filename = "sequence.txt"
    numbers = load_sequence(filename)
    if numbers is None or len(numbers) == 0:
        print("No valid numbers loaded. Please check your sequence.txt file.")
        return
    
    plot_sequence(numbers)
    diffs = plot_differences(numbers)
    plot_autocorrelation(numbers)
    plot_scatter(numbers)

if __name__ == '__main__':
    main()
