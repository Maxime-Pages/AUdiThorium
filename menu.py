from doc import about, header
import os

def menu():
    while True:
        os.system("clear")
        header()
        choice = input("""AUdiThorium:
1. Audit Système seul
2. Audit Apache seul
3. Audit Sytèe & Apache
4. A propos
5. Quitter
>""")
        try:
            choice = int(choice)
        except Exception:
            continue
        if choice == 1:
            pass # todo
        elif choice == 2:
            pass # todo
        elif choice == 3:
            pass # todo
        elif choice == 4:
            about()
        elif choice == 5:
            break

if __name__ == "__main__":
    menu()
