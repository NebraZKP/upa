import sys

def concatenate_files(output_file, input_files):
    concatenated_content = ""
    for file_path in input_files:
        with open(file_path, 'r') as file:
            concatenated_content += file.read()
    with open(output_file, 'w') as outfile:
        outfile.write(concatenated_content)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python concatenate_files.py output_file.txt file1.txt file2.txt ...")
        sys.exit(1)

    output_file = sys.argv[1]
    input_files = sys.argv[2:]
    concatenate_files(output_file, input_files)
    print(f"Concatenated contents written to {output_file}")
