ciphertext = "odroboewscdrolocdcwkbdmyxdbkmdzvkdpybwyeddrobo"

for key in range(1, 26):
    decrypted = ""
    for char in ciphertext:
    	shifted = (ord(char) - ord('a') - key) % 26
    	decrypted += chr(shifted + ord('a'))
    print(f"Key {key}: {decrypted}")
