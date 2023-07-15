import os
import re
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def extract_data(filename):
    with open(filename) as f:
        lines = f.readlines()
    
    data = []
    client_id = None
    total_samples = None
    benign_samples = None
    attack_samples = None

    for line in lines:
        if "Client ID" in line:
            if client_id is not None:
                data.append((client_id, total_samples, benign_samples, attack_samples))
            match = re.search(r'\d+', line)
            if match:
                client_id = int(match.group())
            total_samples = None
            benign_samples = None
            attack_samples = None
        elif "fl_X_train.shape" in line:
            match = re.search(r'\((\d+),', line)
            if match:
                total_samples = int(match.group(1))
        elif "fl_y_train.value_counts()" in line:
            benign_samples = 0
            attack_samples = 0
        elif "Name: label" not in line and "fl_y_train.unique()" not in line and line.strip():
            parts = line.split()
            if len(parts) == 2:
                label, count = map(int, parts)
                if label == 0:
                    benign_samples = count
                else:
                    if len(parts) == 2:
                        label, count = map(int, parts)
                        if label == 0:
                            benign_samples = count
                        else:
                            if attack_samples is None:
                                attack_samples = 0
                            attack_samples += count
    
    if client_id is not None:
        data.append((client_id, total_samples, benign_samples, attack_samples))
   
    return data

def plot_data(data, output_filename):
    data_array = np.array(data)
    client_ids = data_array[:, 0]
    total_samples = data_array[:, 1]
    benign_samples = data_array[:, 2]
    attack_samples = data_array[:, 3]

    bar_width = 0.2
    r1 = np.arange(len(client_ids))
    r2 = [x + bar_width for x in r1]
    r3 = [x + bar_width for x in r2]

    plt.figure(figsize=(15, 7))
    plt.bar(r1, total_samples, color='b', width=bar_width, edgecolor='grey', label='Total Samples')
    plt.bar(r2, benign_samples, color='g', width=bar_width, edgecolor='grey', label='Benign Samples')
    plt.bar(r3, attack_samples, color='r', width=bar_width, edgecolor='grey', label='Attack Samples')

    plt.xlabel('Client ID', fontweight='bold')
    plt.xticks([r + bar_width for r in range(len(client_ids))], client_ids)
    plt.ylabel('Sample Count')
    plt.legend()

    # The plot title should be the name of the current directories parent directory name + current directory name
    title = os.path.basename(os.path.dirname(os.path.dirname(output_filename))) + " - " + os.path.basename(os.path.dirname(output_filename))
    plt.title(title)

    plt.savefig(output_filename, format='png')
    plt.show()
    plt.close()

def process_directory(root_dir):
    for subdir, dirs, files in os.walk(root_dir):
        print(f"Examining directory: {subdir}")
        for file in files:
            if file == "Class Split Info.txt":
                print(f"Found Class Split Info.txt")
                input_file = os.path.join(subdir, file)
                data = extract_data(input_file)
                output_file = os.path.join(subdir, "Class_split_info.png")
                plot_data(data, output_file)

# Example usage:
root_directory = "."
process_directory(root_directory)
