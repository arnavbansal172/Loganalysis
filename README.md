# Loganalysis
VRV Security task - LOG analysis

Hello this is Arnav Bansal
VRV Security's assignment

## Overview

This project is a log analysis tool designed to analyze web server logs. It provides functionalities to count requests per IP address, count requests per endpoint, identify potential brute force attempts, and save the results to a CSV file.

## How It Works

The script performs the following tasks:

1. **Count Requests per IP Address**: Reads the log file and counts the number of requests made by each IP address.
2. **Count Requests per Endpoint**: Reads the log file and counts the number of requests made to each endpoint.
3. **Identify Brute Force Attempts**: Identifies IP addresses with a high number of failed login attempts, indicating potential brute force attacks.
4. **Save Results to CSV**: Saves the analysis results to a CSV file for further review.

## How to Use

1. **Prepare the Log File**: Ensure you have a log file in a readable format.
2. **Run the Script**: Execute the script and provide the path to the log file when prompted.
3. **View Results**: The script will display the analysis results in the console and save them to a CSV file named `log_analysis_results.csv`.

## Example Usage

1. Place your log file in an accessible directory.
2. Run the script:
    ```sh
    python log_analysis.py
    ```
3. Enter the path to your log file when prompted:
    ```
    Enter the path to the log file: /path/to/your/logfile.log
    ```
4. Review the results displayed in the console and check the `log_analysis_results.csv` file for detailed output.

## Dependencies

- Python 3.x
- `re` module (for regular expressions)
- `sys` module (for system-specific parameters and functions)
- `csv` module (for CSV file operations)
- `collections.Counter` (for counting hashable objects)

## Functions

- `count_requests_per_ip_address(log_file)`: Counts and prints the number of requests per IP address.
- `count_requests_per_endpoint(log_file)`: Counts and prints the number of requests per endpoint.
- `identify_brute_force_attempts(log_file, threshold=10)`: Identifies and prints IP addresses with failed login attempts exceeding the threshold.
- `save_to_csv(ip_requests, endpoints, suspicious_activity)`: Saves the analysis results to a CSV file.

## Main Execution

The `main()` function orchestrates the execution of the above functions, prompting the user for the log file path and displaying the results.

## Note

Ensure the log file is in the correct format and accessible by the script to avoid errors.

## Installation

To run this project, you need to have Python 3.x installed on your machine. You can download it from the [official Python website](https://www.python.org/downloads/).

### Install Required Packages

You can install the required packages using `requirements.txt` file

Then, run the following command to install the dependencies:

```sh
pip install -r requirements.txt
```

## How to Run

To run this project, follow these steps:

1. **Clone the Repository**: Clone the repository to your local machine using:
    ```sh
    git clone https://github.com/yourusername/Loganalysis.git
    ```
2. **Navigate to the Project Directory**: Change to the project directory:
    ```sh
    cd Loganalysis
    ```
3. **Prepare the Log File**: Ensure you have a log file in a readable format.
4. **Run the Script**: Execute the script and provide the path to the log file when prompted:
    ```sh
    python log_analysis.py
    ```
5. **View Results**: The script will display the analysis results in the console and save them to a CSV file named `log_analysis_results.csv`.

