import argparse

def find_matching_brace(text, start_pos):
    """
    Finds the position of the matching closing brace for the opening brace at the given start position.

    Args:
        text (str): The text containing the braces.
        start_pos (int): The position of the opening brace.

    Returns:
        int: The position of the matching closing brace, or -1 if no match is found.
    """
    open_braces = 0
    for pos in range(start_pos, len(text)):
        if text[pos] == '{':
            open_braces += 1
        elif text[pos] == '}':
            open_braces -= 1
            if open_braces == 0:
                return pos
    return -1

def extract_code_sections(yul_code):
    """
    Extracts the 'code' sections from the Yul code. The first section extracted contains
    the EVM instructions for contract creation. The second section contains the contract's
    'Runtime' code.

    Args:
        yul_code (str): The Yul code containing the objects and code sections.

    Returns:
        tuple: Two strings containing the 'code' sections for contract creation and 'Runtime',
        or (None, None) if the pattern does not match.
    """
    creation_start = yul_code.find('object "plonk_verifier" {')
    if creation_start == -1:
        return None, None

    creation_code_start = yul_code.find('code {', creation_start)
    if creation_code_start == -1:
        return None, None

    creation_code_start += len('code')
    creation_code_end = find_matching_brace(yul_code, creation_code_start)
    if creation_code_end == -1:
        return None, None

    runtime_start = yul_code.find('object "Runtime" {', creation_code_end)
    if runtime_start == -1:
        return None, None

    runtime_code_start = yul_code.find('code {', runtime_start)
    if runtime_code_start == -1:
        return None, None

    runtime_code_start += len('code')
    runtime_code_end = find_matching_brace(yul_code, runtime_code_start)
    if runtime_code_end == -1:
        return None, None

    creation_code = yul_code[creation_code_start:creation_code_end].strip()
    runtime_code = yul_code[runtime_code_start:runtime_code_end].strip()

    return creation_code, runtime_code

def split_yul_code(input_filename, output_filename1, output_filename2):
    """
    Separates the Yul code from the input file into two files for the contract creation and 'Runtime' objects.
    Input is expected to be the 'plonk_verifier' Yul code produced by the 'snark-verifier' library.

    Args:
        input_filename (str): The input file containing Yul code.
        output_filename1 (str): The output file for the contract creation code section.
        output_filename2 (str): The output file for the runtime code section.
    """
    with open(input_filename, 'r') as file:
        yul_code = file.read()

    creation_code, runtime_code = extract_code_sections(yul_code)
    if creation_code is None or runtime_code is None:
        print("The Yul code structure does not match the expected pattern.")
        return

    # Prepare the full Yul code sections for output
    output_code1 = f'object "plonk_verifier" {{\n    code {{{creation_code}\n    }}\n}}'
    output_code2 = f'object "Runtime" {{\n    code {{{runtime_code}\n    }}\n}}'

    # Write the separated code sections to the output files
    with open(output_filename1, 'w') as file1:
        file1.write(output_code1 + "\n}")  # Add closing brace

    with open(output_filename2, 'w') as file2:
        file2.write(output_code2 + "\n}")  # Add closing brace

    print(f"Code sections successfully written to {output_filename1} and {output_filename2}.")

def main():
    parser = argparse.ArgumentParser(description='Separate Yul code into two files.')
    parser.add_argument('input_filename', type=str, help='The input file containing Yul code.')
    parser.add_argument('output_filename1', type=str, help='The output file for the contract creation code section.')
    parser.add_argument('output_filename2', type=str, help='The output file for the runtime code section.')

    args = parser.parse_args()

    split_yul_code(args.input_filename, args.output_filename1, args.output_filename2)

if __name__ == '__main__':
    main()
