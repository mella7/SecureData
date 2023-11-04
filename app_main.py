from app_functions import authentification
from app_functions import display_menu
from app_functions import chiff 
from app_functions import hachage
from app_functions import auth 
import sys
    
def app():
    while True:
        display_menu()
        choice = input("Enter your choice: ")
        choice = choice.upper()
        
        match choice:
            case "A":
                display_menu() 
            case "B":
                auth()
            case "B1" if authentification():
                hachage()
            case "B2" if authentification():
                chiff()
            case "C":
                print("Goodbye!")
                sys.exit()
            case _:
                print("Invalid choice. Please enter a valid option or you are not authenticated")
app()