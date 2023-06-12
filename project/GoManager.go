package main

import (
	"crypto/aes"
        "crypto/cipher"
        "encoding/base64"
	"fmt"
	"os"
	"bufio"
	"strings"
	"os/exec"
)

const file string = "saveData"

func main() {

	var sel string 

	looper: for {
		clear()
		fmt.Println("0: Exit\n1: New password\n2: Delete password\n3: Check Passwords")
		fmt.Scanln(&sel)

		switch sel {

			case "0":
				break looper
			case "1":
				addNewPass()
			case "2":
				removePassword()
			case "3":
				getPassword()
			default:
				fmt.Println("Not an option.\n try ''help''")
		}
	}


}
//prints the username, password, and application name
func printData(a, b, c string) {
	clear()
	var d string
	
		fmt.Println("\nAppname:" ,a, "\nPassword:", b, "\nUsername:", c,)
		fmt.Println("press anything to continue")
		fmt.Scanln(&d)
		switch d {
		case "0":
			return
		default:
			return
		}
	

}

//takes user input so it can fetch the user's password data
func getPassword() {
	
	looped: for {
		clear()
		printLines()
		var a int
		fmt.Println("select a number")
		fmt.Scanln(&a)
		
		if a == 0 {
			break looped
		}

		m := getString(a)
		mf, err := Decrypt(m)
		splitString := strings.Split(mf, ":")
		app := splitString[0]
		user := splitString[1]
		pass := splitString[2]
		check(err)
		printData(app, user, pass)
		//fmt.Println("\nAppname:" ,app, "\nPassword:", pass, "\nUsername:", user,)
	}
}
// return string at index
func getString(index int) string {
	
	fileLines := fileLines(file)

        return fileLines[index]


}

//asks for password and adds it to the file
func addNewPass() {
	clear()
	var a, b, c string

	fmt.Println("Type app name")
	fmt.Scanln(&a)
	fmt.Println("Type new username")
        fmt.Scanln(&b)
	fmt.Println("Type new password")
        fmt.Scanln(&c)
	
	cat := fmt.Sprintf("%s:%s:%s", a, b, c)

	//youll want to encrypt var a, at about here
	enc, err := Encrypt(cat)
	check(err)
	addPassword(enc)
	
}
//add's string to file
func addPassword(str string) {
	
        f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0644)
        check(err)
        newLine := str
        _, err = fmt.Fprintln(f, newLine)
        if err != nil {
                fmt.Println(err)
                f.Close()
                return
        }
        err = f.Close()
        check(err)
        

}
//take user input to delete a password from the list
func removePassword() {
	
	printLines()
        var a int
        fmt.Println("Type password to remove")
        fmt.Scanln(&a)
        if a == 0 {
		return
	}

	fmt.Println("removed", a)

        removeFromList(a)
	
}
//removes password from list
func removeFromList(remove int) {

        /*filePath := file
        readFile, err := os.Open(filePath)

        check(err)

        fileScanner := bufio.NewScanner(readFile)
        fileScanner.Split(bufio.ScanLines)
        var fileLines []string

        for fileScanner.Scan() {
                fileLines = append(fileLines, fileScanner.Text())
        }

        readFile.Close()*/
	
	fileLines := fileLines(file)

	kill := os.Remove(file)
        create, err := os.Create(file)
        defer create.Close()
        check(kill)
        check(err)
	

	copyArray := make([]string, len(fileLines))
        for i, value := range fileLines {
        	
		if i == remove {
			fmt.Println(value)
			continue
		} else {

			/*enc, err := Encrypt(value)
		        check(err)*/
			
			copyArray[i] = value
			//you'll want to encrypt every string going into copyArray
			addPassword(copyArray[i])
		}
    	}
	
	//return copyArray

}
//prints out fileLines array which is an array made up of the list from file
func printLines() {

        i := 0
	
	fileLines := fileLines(file)

        var line string
        for _, line = range fileLines {
		
		d, err := Decrypt(line)
		check(err)

		splitString := strings.Split(d, ":")
                str := splitString[0]

                fmt.Println(i, str)
                i++

        }
}
//declares file lines, which makes an array out of the current list in the text file. It's the back bone of this whole operation.
func fileLines(f string) []string {

	filePath := f
        readFile, err := os.Open(filePath)
        check(err)

        fileScanner := bufio.NewScanner(readFile)
        fileScanner.Split(bufio.ScanLines)
        var fileLines []string


	        for fileScanner.Scan() {
                fileLines = append(fileLines, fileScanner.Text())
        }

        readFile.Close()

	return fileLines
}

//check function to handle errors
func check(e error) {

        if e != nil{
        	panic(e)
        }
}
//clear function to clear the screen.
func clear() {

        cmd := exec.Command("clear")
        cmd.Stdout = os.Stdout
        cmd.Run()
}

var bytes = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}

const MySecret string = "abc&1*~#^2^#s0^=)^^7%b34"

func Encode(b []byte) string {
        return base64.StdEncoding.EncodeToString(b)
}

// Encrypt method is to encrypt the passwords
func Encrypt(text string) (string, error) {

        block, err := aes.NewCipher([]byte(MySecret))
        check(err)
        plainText := []byte(text)
        cfb := cipher.NewCFBEncrypter(block, bytes)
        cipherText := make([]byte, len(plainText))
        cfb.XORKeyStream(cipherText, plainText)
        return Encode(cipherText), nil
}

func Decode(s string) []byte {
        data, err := base64.StdEncoding.DecodeString(s)
        if err != nil {
                panic(err)
        }
        return data
}

// Decrypt method is to extract back the encrypted text
func Decrypt(text string) (string, error) {

        block, err := aes.NewCipher([]byte(MySecret))
        check(err)
        cipherText := Decode(text)
        cfb := cipher.NewCFBDecrypter(block, bytes)
        plainText := make([]byte, len(cipherText))
        cfb.XORKeyStream(plainText, cipherText)
        return string(plainText), nil
}

