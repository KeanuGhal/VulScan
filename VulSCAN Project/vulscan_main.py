import os
from BTCInput import *
from time import *
import pickle
from datetime import datetime
import hashlib

class Information(object):
    '''
    This is the information needed for the potential area of compromise
    As well as the Indicator of Compromise (IoC)
    '''
    def __init__(self, ref, file_size, md5_hash, sha_hash, date_time):
        self.__ref = ref
        self.__file_size = file_size
        self.__md5_hash = md5_hash
        self.__sha_hash = sha_hash
        self.__date_time = date_time

    def __str__(self):
        template = '''Reference: {0}
File Size: {1}
MD5 Hash: {2}
SHA256 Hash: {3}
Date and Time of Input: {4}'''
        return template.format(self.__ref, self.__file_size, self.__md5_hash,
                               self.__sha_hash, self.__date_time)
    
    @property
    def ref(self):
        return self.__ref
    
    @property
    def file_size(self):
        return self.__file_size
    
    @property
    def md5_hash(self):
        return self.__md5_hash

    @property
    def sha_hash(self):
        return self.__sha_hash

class IoC(Information): #indicator of compromise
    
    def __init__(self, ref, file_size, md5_hash, sha_hash, date_time):
        super().__init__(ref, file_size, md5_hash, sha_hash, date_time)


class AoC(Information): #area of compromise to be scanned

    def __init__(self, ref, file_size, md5_hash, sha_hash, date_time):
        super().__init__(ref, file_size, md5_hash, sha_hash, date_time)


class VulScan:
    
    def __init__(self):
        self.__IoC_dictionary = {}
        self.__AoC_dictionary = {}
    
    def save(self, ioc_filename, aoc_filename):
        '''
        Saves the IoC and the AoC dictionaries
        Data is stored in binary as pickled file
        Exceptions will be raised if the save fails
        '''
        with open(ioc_filename, 'wb') as ioc_file:
            pickle.dump(self.__IoC_dictionary, ioc_file)
        with open(aoc_filename, 'wb') as aoc_file:
            pickle.dump(self.__AoC_dictionary, aoc_file)

    def load_file(self, ioc_filename, aoc_filename):
        try:
            if os.path.getsize(ioc_filename) > 0:
                with open(ioc_filename, 'rb') as ioc_file:
                    self.__IoC_dictionary = pickle.load(ioc_file)
                print('The IoC list has been loaded.')
            else:
                print('The IoC file is empty. Creating a blank IoC dictionary.')
        except FileNotFoundError:
            print('The IoC file cannot be found. Creating a blank IoC dictionary.')

        try:
            if os.path.getsize(aoc_filename) > 0:
                with open(aoc_filename, 'rb') as aoc_file:
                    self.__AoC_dictionary = pickle.load(aoc_file)
                print('The AoC list has been loaded.')
            else:
                print('The AoC file is empty. Creating a blank AoC dictionary.')
        except FileNotFoundError:
            print('The AoC file cannot be found. Creating a blank AoC dictionary.')
   

    def add_new_IoC(self, ref_IoC):
        '''
        Checks if an IoC has already been added
        The item is indexed on the ref value 
        Raises an exception if the IoC was 
        already added.
        '''
        if ref_IoC.ref in self.__IoC_dictionary:
            raise Exception('IoC already added') 
        self.__IoC_dictionary[ref_IoC.ref] = ref_IoC

    def add_new_AoC(self, ref_AoC):
        '''
        Checks if an AoC has already been added
        The item is indexed on the ref value 
        Raises an exception if the AoC was 
        already added.
        '''
        if ref_AoC.ref in self.__AoC_dictionary:
            raise Exception ('AoC name already used')
        self.__AoC_dictionary[ref_AoC.ref] = ref_AoC

    # allows you to view items from the IoC ref dictionary, returns None if nothing is found
    def view_IoC(self, ref):
        '''
        Allows you to view items from the IoC ref dictionary, returns None if nothing is found
        '''
        return self.__IoC_dictionary.get(ref, None)
    
    # allows you to view items from the IoC ref dictionary, returns None if nothing is found       
    def view_AoC(self, ref):
        '''
        Allows you to view items from the AoC ref dictionary, returns None if nothing is found
        '''
        return self.__AoC_dictionary.get(ref, None)
        
    #option to remove an IoC if your systems patched the issue and its no longer deemed an IoC
    def remove_IoC(self, ref):
        if ref in self.__IoC_dictionary:
            del self.__IoC_dictionary[ref]
            print (f"IoC '{ref}' has been deleted.")
        else:
            print('The IoC you entered cannot be found.')

    #option to remove an AoC if this area has been dealt with or no longer exists. 
    def remove_AoC(self, ref):
        if ref in self.__AoC_dictionary:
            del self.__AoC_dictionary[ref]
            print(f"This AoC '{ref}' has been deleted.")
        else:
            print('The AoC you entered does not exist.')

    # View the IoC list
    def list_IoCs(self):
        IoC_ref = map(str, self.__IoC_dictionary.values())
        IoC_ref_list = '\n'.join(IoC_ref)
        template = ''' Indicators of Compromises Reported

{0}
'''
        return template.format(IoC_ref_list)

    # View the AoC list
    def list_AoCs(self):
        AoC_ref = map(str, self.__AoC_dictionary.values())
        AoC_ref_list = '\n'.join(AoC_ref)
        template = '''Areas of Compromises Reported

{0}
'''
        return template.format(AoC_ref_list)

    #gets file size
    def get_file_size(self, file_path):
        '''
        Gets file size
        '''
        return os.path.getsize(file_path)
    
    #this gets us the md5 hash, using chunk sizing to read the file more methodically
    def get_md5_hash(self, file_path):
        hash_md5 = hashlib.md5()
        with open(file_path, 'rb') as h:
            for chunk in iter(lambda: h.read(4000),b''):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    #this gets us the SHA256 hash, same workflow as the MD5
    def get_sha256_hash(self, file_path):
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as h:
            for chunk in iter(lambda: h.read(4000), b''):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def scan_ioc(self):
        '''
        Adds a new IoC via scanning the path
        Adds the IoC and stores it in the IoC scanner
        '''
        # Prompt the user for the IoC reference
        while True:
            ioc_ref = read_text('Enter a reference name for the IoC: ')
            if ioc_ref in self.__IoC_dictionary:
                print(f"This reference name '{ioc_ref}' is currently in use. Please type another name.")
            else:
                break
        
        file_path = read_text('Enter the file path of the folder/file: ')

        # This checks if the file/folder exists
        if not os.path.exists(file_path):
            print('The file/folder you are searching for does not exist.')
            return

        if os.path.isdir(file_path):
            # If the path is a directory, process each file in it
            counter = 1
            for root, dirs, files in os.walk(file_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    self.process_ioc_file(ioc_ref, full_path, counter)
                    counter += 1
        else:
            # If the path is a file, process the file
            self.process_ioc_file(ioc_ref, file_path, 1)

    def process_ioc_file(self, ioc_ref, file_path, counter):
        '''
        Processes a single file, calculates hashes, and adds IoC
        '''
        try:
            file_size = self.get_file_size(file_path)
            md5_hash = self.get_md5_hash(file_path)
            sha256_hash = self.get_sha256_hash(file_path)
            date_time = datetime.now()

         # Append the counter to the original IoC reference
            unique_ioc_ref = f"{ioc_ref}_{counter}"

            # Create a new IoC and add to dictionary
            new_ioc = IoC(unique_ioc_ref, file_size, md5_hash, sha256_hash, date_time)
            self.add_new_IoC(new_ioc)
            print(f"IoC '{unique_ioc_ref}' for file '{file_path}' is saved.")
        except Exception as e:
            print(f"Failed to process file '{file_path}': {e}")


    def scan_aoc(self):
        '''
        Adds a new AoC via scanning the path
        Adds the AoC and stores it in the AoC scanner
        '''
        # Prompt the user to input an AoC reference
        while True:
            aoc_ref = read_text('Enter a reference name for the AoC: ')
            if aoc_ref in self.__AoC_dictionary:
                print(f"The reference name {aoc_ref} is already in use. Select anothe reference name.")
            else:
                break
        
        file_path = read_text('Enter the file path of the folder/file: ')

        # This checks if the file/folder exists
        if not os.path.exists(file_path):
            print('The file/folder you are searching for does not exist')
            return

        if os.path.isdir(file_path):
            # If the path is a directory, process each file in it
            counter = 1
            for root, dirs, files in os.walk(file_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    self.process_file(aoc_ref, full_path, counter)
                    counter += 1
        else:
            # If the path is a file, process the file
            self.process_file(aoc_ref, file_path, 1)

    def process_file(self, aoc_ref, file_path, counter):
        '''
        Processes a single file, calculates hashes, and adds AoC
        '''
        try:
            file_size = self.get_file_size(file_path)
            md5_hash = self.get_md5_hash(file_path)
            sha256_hash = self.get_sha256_hash(file_path)
            date_time = datetime.now()

            # Append the counter to the original AoC reference
            unique_aoc_ref = f"{aoc_ref}_{counter}"

            # Create a new AoC and add to dictionary
            new_aoc = AoC(unique_aoc_ref, file_size, md5_hash, sha256_hash, date_time)
            self.add_new_AoC(new_aoc)
            print(f"AoC '{unique_aoc_ref}' for file '{file_path}' is saved.")
        except Exception as e:
            print(f"Failed to process file '{file_path}': {e}")

    
    def scanner_AoC(self, aoc):
        '''
        This allows a user to scan a workspace or AoC
        Knowing the reference number is important
        You can always view the AoC list via the main menu
        '''
        matches = []
        for ioc in self.__IoC_dictionary.values():
            if (ioc.file_size == aoc.file_size and ioc.md5_hash == aoc.md5_hash and ioc.sha_hash == aoc.sha_hash):
                matches.append(ioc)

        if matches:
            print('This AoC has found matches to these IoCs')
            for match in matches:
                print(match)
        else:
            print('This AoC is clear for now. No IoCs found.')


        


class VulScanShellApplication:

    def __init__(self, ioc_filename, aoc_filename):
        '''
        Manages the Scan data
        Displays a message if the load fails and creates a new scanner
        '''
        self.ioc_filename = ioc_filename
        self.aoc_filename = aoc_filename
        self.__scanner = VulScan()
        try:
            self.__scanner.load_file(self.ioc_filename, self.aoc_filename)
            print ('The VulScan data has successfully loaded the IoC and AoC saved data.')
        except FileNotFoundError:
            print('IoC and AoC stored data not found. This VulScan will have no saved history.')
    
    def ensure_files_exist(self):
        for filename in [self.ioc_filename, self.aoc_filename]:
            if not os.path.exists(filename):
                with open(filename, 'wb') as f:
                    pass  # Create an empty file if it doesn't exist
    
    
    def save_scanner_data(self):
        self.__scanner.save(self.ioc_filename, self.aoc_filename)
        print('Scanner data saved.')
    
    def load_scanner_data(self):
        try:
            self.__scanner.load_file(self.ioc_filename, self.aoc_filename)
            print('Data from the IoC and AoC file has been loaded.')
        except FileNotFoundError:
            print('Cannot find scanner files')

    def add_IoC_manual (self):
        '''
        Adds a new IoC when you have the information needed to input
        Adds the IoC and stores it in the IoC scanner
        '''
        ref = read_text ('Enter a reference name for the IoC: ')
        
        #Checks to see if the IoC reference name is already in use
        if ref in self.__scanner._VulScan__IoC_dictionary:
            print('This IoC is already in use.')
            return
        
        while True:
            try:
                file_size = float(read_float('Enter the byte size of the file (only numbers): '))
                if file_size <= 0:
                    raise ValueError ('File size must be a positive number')
                break
            except ValueError as e:
                print(e)
                print('Please enter a valid file size')
                return
        #Validate the MD5 input
        while True:
                md5_hash = read_text('Enter md5 hash: ')
                if len(md5_hash) == 32 and all(c in '0123456789abcdefABCDEF' for c in md5_hash):
                    break
                else:
                    print('Invalid length and/or invalid text. Must be a 32 character hexidecimal string.')
                    return
        #Validate the SHA256 input
        while True:
            sha256_hash = read_text ('Enter sha256 hash: ')
            if len(sha256_hash) == 64 and all (c in '0123456789abcdefABCDEF' for c in sha256_hash):
                break
            else:
                print('Invalid length and/or invalid text. Must be a 64 character hexidecimal string')
                return
        date_time = datetime.now()

        #Now create the new IoC instance
        new_ioc = IoC(ref, file_size, md5_hash, sha256_hash, date_time)
        self.__scanner.add_new_IoC(new_ioc)
        print(f"The '{ref}' is saved.")

    def removing_ioc(self):
        ref = read_text('Enter the IoC reference you would like to remove: ')
        self.__scanner.remove_IoC(ref)
    
    def removing_aoc(self):
        ref = read_text('Enter the AoC reference you would like to remove: ')
        self.__scanner.remove_AoC(ref)

    def main_menu(self):

        prompt = '''Welcome to VulScan 0.1
1. Automatically Input IoC
2. Automatically Input AoC
3. Manually Input IoC
4. View IoC or AoC List
5. Remove IoC or AoC
6. Scanner
7. Exit

Enter your command: '''
        
        while (True):
            command = read_int_ranged(prompt, 1, 7)
            if command == 1:
                self.__scanner.scan_ioc()
            elif command == 2:
                self.__scanner.scan_aoc()
            elif command == 3:
                self.add_IoC_manual()
            elif command == 4:
                list_type = read_text(prompt="Type 'a' for IoC List and 'b' for AoC List: ").strip().lower()
                if list_type == 'a':
                    print(self.__scanner.list_IoCs())
                elif list_type == 'b':
                    print(self.__scanner.list_AoCs())
                else:
                    print("Invalid input. Please enter 'a' or 'b'")
            elif command == 5:
                remove_type = read_text(prompt="Type 'a' to remove IoC from list and 'b' to remove an AoC: ").strip().lower()
                if remove_type == 'a':
                    self.removing_ioc()
                elif remove_type == 'b':
                    self.removing_aoc()
                else:
                    print("Invalid input. Please enter 'a' or 'b'")
            elif command == 6:
                aoc_ref = read_text('Enter the AoC reference you want to scan: ')
                aoc = self.__scanner.view_AoC(aoc_ref)
                if aoc:
                    self.__scanner.scanner_AoC(aoc)
                else:
                    print('The AoC reference you entered does not exist.')
            elif command == 7:
                self.__scanner.save(self.ioc_filename, self.aoc_filename)
                print('Scanner data saved.')
                break

if __name__ == '__main__':
    app = VulScanShellApplication('IoCList.pickle', 'AoCList.pickle')
    app.main_menu()