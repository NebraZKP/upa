import re
import csv

def parse_logs(input_file, output_file):
    # Regular expressions to match the beginning of each circuit's log section and extract configurations
    circuit_start_patterns = {
        'UBV': re.compile(r'^Begin UBV with config (.*)$'),
        'Keccak': re.compile(r'^Begin Keccak with config (.*)$'),
        'UniversalOuter': re.compile(r'^Begin UniversalOuter with config (.*)$')
    }

    # Regular expressions to extract other quantities of interest
    advice_cells_pattern = re.compile(r'(\d+) advice cells')
    lookup_cells_pattern = re.compile(r'(\d+) lookup advice cells')
    num_advice_columns_pattern = re.compile(r'num_advice_per_phase: \[(\d+)')
    num_lookup_advice_columns_pattern = re.compile(r'num_lookup_advice_per_phase: \[(\d+)')
    num_fixed_columns_pattern = re.compile(r'num_fixed: (\d+)')
    proving_time_pattern = re.compile(r'Time: ([\d.]+)s')
    gas_cost_pattern = re.compile(r'Gas cost per proof: (\d+)')

    # Initialize variables to hold the current state of parsing
    current_circuit = None
    data = []

    with open(input_file, 'r') as file:
        for line in file:
            line = line.strip()
            # Check if the line indicates the start of a new circuit's logs
            for circuit_name, pattern in circuit_start_patterns.items():
                match = pattern.match(line)
                if match:
                    config = match.group(1)
                    # For Keccak it's the total batch size that matters:
                    if circuit_name == 'Keccak':
                        # Extract inner and outer batch sizes and calculate total_batch_size
                        inner_batch_size_match = re.search(r'inner_batch_size: (\d+)', config)
                        outer_batch_size_match = re.search(r'outer_batch_size: (\d+)', config)
                        if inner_batch_size_match and outer_batch_size_match:
                            inner_batch_size = int(inner_batch_size_match.group(1))
                            outer_batch_size = int(outer_batch_size_match.group(1))
                            total_batch_size = inner_batch_size * outer_batch_size
                            # Reconstruct the configuration string with total_batch_size
                            config = re.sub(r'inner_batch_size: \d+, outer_batch_size: \d+', f'total_batch_size: {total_batch_size}', config)

                    current_circuit = {
                        'circuit_name': circuit_name,
                        'configuration': config,
                        'num_advice_cells': '',
                        'num_lookup_cells': '',
                        'num_advice_columns': '',
                        'num_lookup_advice_columns': '',
                        'num_fixed_columns': '',
                        'proving_time': '',
                        'gas_cost': ''
                    }

            # If we're within a circuit's log section, try to extract information
            if current_circuit:
                if advice_cells_match := advice_cells_pattern.search(line):
                    current_circuit['num_advice_cells'] = advice_cells_match.group(1)
                if lookup_cells_match := lookup_cells_pattern.search(line):
                    current_circuit['num_lookup_cells'] = lookup_cells_match.group(1)
                if advice_columns_match := num_advice_columns_pattern.search(line):
                    current_circuit['num_advice_columns'] = advice_columns_match.group(1)
                if lookup_advice_columns_match := num_lookup_advice_columns_pattern.search(line):
                    current_circuit['num_lookup_advice_columns'] = lookup_advice_columns_match.group(1)
                if fixed_columns_match := num_fixed_columns_pattern.search(line):
                    current_circuit['num_fixed_columns'] = fixed_columns_match.group(1)
                if proving_time_match := proving_time_pattern.search(line):
                    current_circuit['proving_time'] = proving_time_match.group(1)
                    # For circuits other than Universal Outer, proving time marks the end of the section
                    if current_circuit['circuit_name'] != 'UniversalOuter':
                        data.append(current_circuit)
                        current_circuit = None
                if gas_cost_match := gas_cost_pattern.search(line):
                    current_circuit['gas_cost'] = gas_cost_match.group(1)
                    # For Universal Outer, the gas cost marks the end of the section
                    if current_circuit['circuit_name'] == 'UniversalOuter':
                        data.append(current_circuit)
                        current_circuit = None
    fieldnames = ['circuit_name', 'configuration', 'num_advice_cells', 'num_lookup_cells', 'num_advice_columns', 'num_lookup_advice_columns', 'num_fixed_columns', 'proving_time', 'gas_cost']

    write_to_csv(data, output_file, fieldnames)

def average_duplicates(input_csv, output_csv):
    entries = {}
    # Read the existing CSV and group by circuit name and configuration
    with open(input_csv, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            key = (row['circuit_name'], row['configuration'])
            if key not in entries:
                entries[key] = []
            entries[key].append(row)

    averaged_data = []
    # Process each group to average the numerical values and count sample size
    for key, group in entries.items():
        averaged_entry = {col: '' for col in ['circuit_name', 'configuration', 'num_advice_cells', 'num_lookup_cells', 'num_advice_columns', 'num_lookup_advice_columns', 'num_fixed_columns', 'proving_time', 'gas_cost', 'sample_size']}  # Adjusted initialization
        averaged_entry['circuit_name'], averaged_entry['configuration'] = key
        sample_size = len(group)
        averaged_entry['sample_size'] = sample_size
        for col in ['num_advice_cells', 'num_lookup_cells', 'proving_time', 'gas_cost', 'num_advice_columns', 'num_lookup_advice_columns', 'num_fixed_columns']:
            values = [float(row[col]) for row in group if row[col] not in ['', 'NA', None]]
            if values:
                averaged_entry[col] = sum(values) / len(values)
            else:
                averaged_entry[col] = ''  # Use an empty string for missing values as per initial write_to_csv definition

        averaged_data.append(averaged_entry)
    fieldnames = ['circuit_name', 'configuration', 'num_advice_cells', 'num_lookup_cells', 'num_advice_columns', 'num_lookup_advice_columns', 'num_fixed_columns', 'proving_time', 'gas_cost', 'sample_size']

    write_to_csv(averaged_data, output_csv, fieldnames)

def extract_ubv_and_keccak_configs(upa_config):
    # Extract fields from the UPA config
    max_num_app_public_inputs = re.search(r'max_num_app_public_inputs: (\d+)', upa_config).group(1)
    inner_batch_size = re.search(r'inner_batch_size: (\d+)', upa_config).group(1)
    outer_batch_size = re.search(r'outer_batch_size: (\d+)', upa_config).group(1)
    total_batch_size = int(inner_batch_size) * int(outer_batch_size)

    # Extracting UBV config parts
    bv_config_match = re.search(r'bv_config: CircuitWithLimbsConfig { ([^}]+) }', upa_config)
    degree_bits, lookup_bits, limb_bits, num_limbs = re.findall(r'(?:degree_bits|lookup_bits|limb_bits|num_limbs): (\d+)', bv_config_match.group(1))

    # Construct the UBV config string with correct order
    ubv_config = f"UniversalBatchVerifierConfig {{ degree_bits: {degree_bits}, lookup_bits: {lookup_bits}, limb_bits: {limb_bits}, num_limbs: {num_limbs}, inner_batch_size: {inner_batch_size}, max_num_public_inputs: {max_num_app_public_inputs} }}"

    # Extracting Keccak config parts
    keccak_config_match = re.search(r'keccak_config: CircuitConfig { ([^}]+) }', upa_config)
    degree_bits_keccak, lookup_bits_keccak = re.search(r'degree_bits: (\d+), lookup_bits: (\d+)', keccak_config_match.group(1)).groups()

    # Construct the Keccak config string with correct order and total_batch_size calculation
    keccak_config = f"KeccakConfig {{ degree_bits: {degree_bits_keccak}, num_app_public_inputs: {max_num_app_public_inputs}, total_batch_size: {total_batch_size}, lookup_bits: {lookup_bits_keccak} }}"

    return ubv_config, keccak_config

def parse_outer_config(configuration):
    # Extract the individual components from the configuration string
    inner_batch_size = re.search(r'inner_batch_size: (\d+)', configuration).group(1)
    outer_batch_size = re.search(r'outer_batch_size: (\d+)', configuration).group(1)
    total_batch_size = int(inner_batch_size) * int(outer_batch_size)
    max_num_public_inputs = re.search(r'max_num_app_public_inputs: (\d+)', configuration).group(1)
    outer_degree_bits = re.search(r'outer_config:.*?degree_bits: (\d+)', configuration).group(1)
    ubv_degree_bits = re.search(r'bv_config:.*?degree_bits: (\d+)', configuration).group(1)
    keccak_degree_bits = re.search(r'keccak_config:.*?degree_bits: (\d+)', configuration).group(1)

    return {
        'inner_batch_size': inner_batch_size,
        'outer_batch_size': outer_batch_size,
        'total_batch_size': str(total_batch_size),  # Converting to string for CSV output consistency
        'max_num_public_inputs': max_num_public_inputs,
        'outer_degree_bits': outer_degree_bits,
        'ubv_degree_bits': ubv_degree_bits,
        'keccak_degree_bits': keccak_degree_bits,
    }

def compile_outer_proving_times(input_csv, output_csv):
    ubv_metrics = {}
    keccak_metrics = {}
    data = []

    with open(input_csv, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            circuit_name = row['circuit_name']
            if circuit_name == 'UBV':
                ubv_metrics[row['configuration']] = row
            elif circuit_name == 'Keccak':
                keccak_metrics[row['configuration']] = row
            elif circuit_name == 'UniversalOuter':
                data.append(row)

    processed_data = []
    for row in data:
        # Deconstruct the configuration into new columns
        config_details = parse_outer_config(row['configuration'])

        # Existing logic to match UBV and Keccak metrics
        upa_config = row['configuration']
        ubv_config, keccak_config = extract_ubv_and_keccak_configs(upa_config)
        ubv_row = ubv_metrics.get(ubv_config, {})
        keccak_row = keccak_metrics.get(keccak_config, {})

        # Compile the new row with additional deconstructed configuration columns
        new_row = {
            **config_details,
            'circuit_name': row['circuit_name'],  # Explicitly set from the original row
            'configuration': upa_config,  # Explicitly set from the original row
            'outer_proving_time': row['proving_time'],
            'gas_cost': row.get('gas_cost', 'NA'),  # Retain gas_cost for Universal Outer
            'ubv_proving_time': ubv_row.get('proving_time', 'NA'),
            'keccak_proving_time': keccak_row.get('proving_time', 'NA'),
            # Include prefixed metrics for UBV and Keccak, and retain metrics for Universal Outer
            **{f'ubv_{k}': ubv_row.get(k, 'NA') for k in ['num_advice_cells', 'num_advice_columns', 'num_lookup_cells', 'num_lookup_advice_columns', 'num_fixed_columns']},
            **{f'keccak_{k}': keccak_row.get(k, 'NA') for k in ['num_advice_cells', 'num_advice_columns', 'num_lookup_cells', 'num_lookup_advice_columns', 'num_fixed_columns']},
            'outer_num_advice_cells': row.get('num_advice_cells', 'NA'),
            'outer_num_advice_columns': row.get('num_advice_columns', 'NA'),
            'outer_num_lookup_cells': row.get('num_lookup_cells', 'NA'),
            'outer_num_lookup_advice_columns': row.get('num_lookup_advice_columns', 'NA'),
            'outer_num_fixed_columns': row.get('num_fixed_columns', 'NA'),
        }

        processed_data.append(new_row)

    # Define new fieldnames including the deconstructed configuration details and the existing metrics
    fieldnames = [
        'circuit_name', 'inner_batch_size', 'outer_batch_size', 'total_batch_size', 'max_num_public_inputs',
        'outer_degree_bits', 'ubv_degree_bits', 'keccak_degree_bits', 'gas_cost', 'outer_proving_time',
        'ubv_proving_time', 'keccak_proving_time',
        'ubv_num_advice_cells', 'ubv_num_advice_columns', 'ubv_num_lookup_cells', 'ubv_num_lookup_advice_columns', 'ubv_num_fixed_columns',
        'keccak_num_advice_cells', 'keccak_num_advice_columns', 'keccak_num_lookup_cells', 'keccak_num_lookup_advice_columns', 'keccak_num_fixed_columns',
        'outer_num_advice_cells', 'outer_num_advice_columns', 'outer_num_lookup_cells', 'outer_num_lookup_advice_columns', 'outer_num_fixed_columns',
        'configuration',
    ]
    write_to_csv(processed_data, output_csv, fieldnames)

def sort_csv_by_columns(input_csv):
    data = []

    # Read the CSV file into a list of dictionaries
    with open(input_csv, mode='r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        data = [row for row in reader]

    # Convert columns used for sorting to appropriate types (int) to ensure correct sorting
    for row in data:
        for col in ['max_num_public_inputs', 'total_batch_size', 'outer_batch_size', 'inner_batch_size', 'outer_degree_bits', 'ubv_degree_bits', 'keccak_degree_bits']:
            row[col] = int(row[col])

    # Sort the data by the specified columns
    sorted_data = sorted(data, key=lambda x: (
        x['max_num_public_inputs'],
        x['total_batch_size'],
        x['outer_batch_size'],
        x['inner_batch_size'],
        x['outer_degree_bits'],
        x['ubv_degree_bits'],
        x['keccak_degree_bits']
    ))

    # Write the sorted list back to the CSV file, overwriting the original
    with open(input_csv, mode='w', newline='', encoding='utf-8') as csvfile:
        fieldnames = reader.fieldnames
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in sorted_data:
            # Convert sorted column values back to strings for CSV output
            for col in ['max_num_public_inputs', 'total_batch_size', 'outer_batch_size', 'inner_batch_size', 'outer_degree_bits', 'ubv_degree_bits', 'keccak_degree_bits']:
                row[col] = str(row[col])
            writer.writerow(row)

def write_to_csv(data, output_file, fieldnames):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in data:
            writer.writerow(row)

def main(input_file, output_file):
    # Extract raw data from logs
    raw_csv_filename = output_file + "_raw.csv"
    parse_logs(input_file, raw_csv_filename)
    # Combine any duplicate config runs
    combined_csv_filename = output_file + "_combined.csv"
    average_duplicates(raw_csv_filename, combined_csv_filename)
    # Match UBV, Keccak proving times to Outer proving times
    processed_csv_filename = output_file + "_processed.csv"
    compile_outer_proving_times(combined_csv_filename, processed_csv_filename)
    # Sort the data
    sort_csv_by_columns(processed_csv_filename)

if __name__ == "__main__":
    import sys
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    main(input_file, output_file)
