#!/usr/bin/env python3
import matplotlib.pyplot as plt

def read_sequence(filename):
    """Read a sequence of integers from the given filename."""
    numbers = []
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    numbers.append(int(line))
                except ValueError:
                    print(f"Skipping invalid line: {line}")
    return numbers

def main():
    filename = "sequence.txt"
    numbers = read_sequence(filename)
    
    if not numbers:
        print("No numbers found in the file.")
        return

    # Create a list of indices for the x-axis
    indices = list(range(len(numbers)))
    # Plot the sequence as a scatter plot
    plt.figure(figsize=(12, 6))
    plt.scatter(indices, numbers, marker='o')
    plt.title("Sequence Scatter Plot from sequence.txt")
    plt.xlabel("Index")
    plt.ylabel("Value")
    plt.grid(True)
    plt.tight_layout()
    
    # Save the plot to a PNG file
    plt.savefig("sequence_scatter_plot.png")

if __name__ == '__main__':
    main()
