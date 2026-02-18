import os
import re

def clean_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    new_lines = []
    extension = os.path.splitext(filepath)[1]

    for line in lines:

        if extension == '.py':

            if re.match(r'^\s*#', line):
                continue

            if '#' in line:


                line = line.split('#')[0] + '\n'


        elif extension == '.rs':
            if re.match(r'^\s*//', line):
                continue
            if '//' in line:
                line = line.split('//')[0] + '\n'


        if line.strip():
            new_lines.append(line)


    with open(filepath, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    print(f"✅ Cleaned: {filepath}")

def main():

    for root, dirs, files in os.walk("."):
        for file in files:

            if file == "clean_comments.py" or ".git" in root or "venv" in root:
                continue

            filepath = os.path.join(root, file)
            

            if file.endswith(".py") or file.endswith(".rs"):
                clean_file(filepath)

if __name__ == "__main__":
    confirm = input("⚠️ ΠΡΟΣΟΧΗ: Αυτό θα σβήσει ΟΛΑ τα σχόλια μόνιμα. Έχεις κάνει backup; (yes/no): ")
    if confirm.lower() == "yes":
        main()
        print("\n✨ Ολα τα αρχεία καθαρίστηκαν!")
    else:
        print("Ακυρώθηκε.")