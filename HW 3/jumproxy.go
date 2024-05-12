package main
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	 "encoding/binary"
	"flag"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"log"
	"net"
	"os"
)

func handshake(secret_key []byte,lp string, host string, port string){

if lp == "" {
		client(secret_key,host,port)
		
		
	} else {
	
		con, err := net.Listen("tcp", ":"+lp)
		if err != nil {
			log.Fatalf("error: %v", err)
		}
		defer con.Close()
		log.Printf("Server listen: %s", lp)

		for {
			connection, err := con.Accept()
			if err != nil {
				log.Fatalf("error: %v", err)
				continue
			}
			go server(secret_key,connection, host,port)
		}
		
		
	}



}
func main() {




	logFile, err := os.OpenFile("jumproxy.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
    	}
    	defer logFile.Close()

  
    	log.SetOutput(logFile)
    	
	var lp string
	var pwd string
	flag.StringVar(&lp, "l", "", "listen port")
	flag.StringVar(&pwd, "k", "", "password")
	flag.Parse()

	arguments := flag.Args()
	if len(arguments) < 2 || pwd == "" {
		fmt.Println("Incorrect Use of jumproxy")
		return
	}
	host:= arguments[0]
	port := arguments[1]

 	pass, err := os.ReadFile(pwd)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	

	secret_key := pbkdf2.Key(pass, []byte("jumproxy-salt"), 4096, 32, sha256.New)
	handshake(secret_key, lp, host, port)

	
}

func server(key []byte,conn net.Conn, host string, port string) {
	defer conn.Close()
	addr:= host+":"+port
	connection, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalf("error: %v", err)
		return
	}
	defer connection.Close()
	
	go decrypt(key,conn, connection) 
	encrypt(key,connection, conn)     
}




func client(key []byte,host string, port string) {
	addr:= host+":"+port
	connection, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	defer connection.Close()


	
	go decrypt(key,connection, os.Stdout) 
	encrypt(key,os.Stdin, connection)     
}

func encrypt(key []byte,src io.Reader, dst io.Writer) {


    block, err := aes.NewCipher(key)
    if err != nil {
        log.Fatalf("error: %v", err)
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        log.Fatalf("error: %v", err)
    }
   
     buffer := make([]byte, 4096) 
        for {
            n, re := src.Read(buffer)
            if re != nil && re != io.EOF {
               
                continue
            }
            if n == 0 {
                break
            }

          
            nonce := make([]byte, gcm.NonceSize())
            if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
                log.Fatalf("error: %v", err)
            }

         
            cipher := gcm.Seal(nonce, nonce, buffer[:n], nil) 
           
            packetlength := len(cipher)
            bufferlength := make([]byte, 4)
            binary.BigEndian.PutUint32(bufferlength, uint32(packetlength))

            if _, err := dst.Write(bufferlength); err != nil {
               
                return
            }

            
            if _, err := dst.Write(cipher); err != nil {
                
                return
            }

            if re == io.EOF {
                break
            }
        }

}

func decrypt(key []byte,src io.Reader, dst io.Writer) {


    block, err := aes.NewCipher(key)
    if err != nil {
        log.Fatalf("error: %v", err)
    }
    
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        log.Fatalf("error: %v", err)
    }
    
     var packetlength uint32
        for {
            
            bufferlength := make([]byte, 4)
            if _, err := io.ReadFull(src, bufferlength); err != nil {
                if err == io.EOF {
                    break
                }
                log.Printf("error: %v", err)
                continue
            }
            packetlength = binary.BigEndian.Uint32(bufferlength)

            
            packet := make([]byte, packetlength)
            if _, err := io.ReadFull(src, packet); err != nil {
                log.Printf("error: %v", err)
                continue
            }

            
            nonce, cipher := packet[:gcm.NonceSize()], packet[gcm.NonceSize():]

          
            plain, err := gcm.Open(nil, nonce, cipher, nil)
            if err != nil {
                log.Printf("error: %v", err)
                continue
            }

            
            if _, err := dst.Write(plain); err != nil {
                log.Printf("error: %v", err)
                continue
            }
        }
    

}


