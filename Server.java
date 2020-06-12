package Server;

//Socket 통신 import
import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

//RSA, AES import
import java.security.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//timestamp import
import java.util.Calendar;
import java.util.Locale;




public class Server {

    private static String AES_key = null; 		//AES 비밀키
    private static String iv_str=null; 			//초기벡터
    public static Socket socket = null;                //Client와 통신하기 위한 Socket
    public static ServerSocket server_socket = null;  //서버 생성을 위한 ServerSocket 
    public static BufferedReader in = null;            //Client로부터 데이터를 읽어들이기 위한 입력스트림
    public static BufferedReader send = null;			  //키보드로부터 읽어들이기 위한 입력스트림
    public static PrintWriter out = null;                //Client로 데이터를 내보내기 위한 출력 스트림
    public static boolean sendTh; 
    public static boolean recvTh;
    
    public static void main(String arg[])
    {
        try{
            server_socket = new ServerSocket();			//Server Socket 생성
            server_socket.bind(new InetSocketAddress("127.0.0.1", 4000)); 
            //Socket에 SocketAddress(IpAddress + Port) 바인딩
            
        }catch(IOException e)
        {
            System.out.println(e.getMessage());
            return;
        }
        try {
            
            socket = server_socket.accept();    //서버가 Client 접속 대기
            
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));    //socket입력스트림 생성
            send = new BufferedReader(new InputStreamReader(System.in));					//키보드 입력스트림 생성
            out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))); //socket출력스트림 생성
            

            KeyPair keypair = CreateRSA_Key();  //RSA Key 생성
            String stringPublicKey = Base64.getEncoder().encodeToString(keypair.getPublic().getEncoded());
            String stringPrivateKey = Base64.getEncoder().encodeToString(keypair.getPrivate().getEncoded());
            //공개키, 개인키를 string형으로 변환
            
        	System.out.println("Private Key : "+ stringPrivateKey);
        	System.out.println("Public Key : "+ stringPublicKey + "\n");
        	//RSA 공개키, 개인키 출력
            
            out.println(stringPublicKey);   //client에게 공개키 전달
            out.flush();
            
            String encryptedAES_key =  in.readLine();	//client로부터 암호화된 AES key받음
            String encryptedIV = in.readLine();			//client로부터 암호화된 IV 받음
            
            System.out.println(">Received AES Key : " + encryptedAES_key);
            System.out.println(">Received IV : " + encryptedIV);
            //받은 AES key 와 IV 출력
            
            AES_key = decryptRSA(encryptedAES_key, keypair.getPrivate());
            System.out.println("Decrypted AES Key : " + AES_key);       
            iv_str = decryptRSA(encryptedIV, keypair.getPrivate());
            System.out.println("Decrypted IV : " + iv_str + "\n");
            //복호화된 AES key와 초기 벡터를 출력
            
            
            secure_chating();  //채팅 루틴
            
            
        }catch(IOException e){
        	
        	System.out.println(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    
    //chating 함수
    public static void secure_chating() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
    {           
		recvTh = true;
		sendTh = true;   
		//thread 시작 전, thread 살아 있음을 명시함
		
    	SendThread();	//send thread
    	RecvThread();	//receive thread
    	
    	while(sendTh || recvTh);		//send thread와 recv thread 끝날떄까지 spin lock  
    }
    
    /*
     * RSA KEY 쌍 생성 함수 
     * server class 내에서만 접근 가능하도록 키 생성 함수를 private로 선언
    * 2048bit RSA 키쌍 생성 
    */
    	private static KeyPair CreateRSA_Key() throws NoSuchAlgorithmException{

    	
    	System.out.println(">Creating RSA Key Pair…");
    	
    	KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA"); //키 생성을 RSA방식으로 지정 
    	SecureRandom Randomkey = new SecureRandom(); //임의의 키 생성 객체
    	
    	gen.initialize(2048, Randomkey); //key 생성자로 2048 bit의 RSA key 생성
    	
    	KeyPair keypair = gen.genKeyPair();
    	
    	
    	return keypair; //키 쌍 return
    }
    
    /*
     RSA복호화 함수 (AES key 복호화)
      암호화된 AES 키를 RSA 개인키로 복호화 
     */  
    	private static String decryptRSA(String encrypted_data, PrivateKey privateKey) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        String decrypted_data = null;

            //만들어진 개인키객체를 기반, 복호화 과정
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            //암호화된 AES key를 복호화하는 과정 . UTF-8사용
            byte[] byteEncrypted_data = Base64.getDecoder().decode(encrypted_data.getBytes("UTF-8"));
            byte[] byteDecrypted_data = cipher.doFinal(byteEncrypted_data);
            decrypted_data = new String(byteDecrypted_data,"UTF-8");

        return decrypted_data;
    }    

	/*
	 * MSG를 AES로 암호화하는 함수 
	 */
    	private static String MSG_encryption(String MSG)
    		throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
    	{
    	byte[] iv=Base64.getDecoder().decode(iv_str.getBytes("UTF-8"));				//초기 벡터 
    	byte[] Byte_AES_key = Base64.getDecoder().decode(AES_key.getBytes("UTF-8"));//AES key
    	  	
		//AES암호모드 CBC 및 PKCS5 padding 설정 ,초기 벡터 설정 
		SecretKeySpec secretkeySpec = new SecretKeySpec(Byte_AES_key,"AES");
		Cipher c =  Cipher.getInstance("AES/CBC/PKCS5Padding");
		
    	IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		c.init(Cipher.ENCRYPT_MODE,secretkeySpec, ivParameterSpec);

    	//AES key로 msg암호화
		byte[] encryptedMSG = c.doFinal(MSG.getBytes("UTF-8"));
		MSG = new String(Base64.getEncoder().encode(encryptedMSG),"UTF-8");
	
    	//암호화된 msg string으로 반환
		return MSG;		
    	}
    	//
    	// MSG 복호화 함수
    	// 
    	private static String MSG_decryption(String MSG) 
    		throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    	
    	byte[] decryptedMSG = null;
    	byte[] iv=Base64.getDecoder().decode(iv_str.getBytes("UTF-8"));			//초기 벡터 설정
    	byte[] Byte_AES_key = Base64.getDecoder().decode(AES_key.getBytes("UTF-8"));
    	
    	//AES복호화모드 CBC 및 PKCS5 패딩 설정 ,초기 벡터 설정 
    	SecretKeySpec secretkeySpec = new SecretKeySpec(Byte_AES_key,"AES");    	
    	Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
    	
    	c.init(Cipher.DECRYPT_MODE, secretkeySpec, ivParameterSpec);

    	//복호화 수행 , UTF-8 사용
    	byte[] byteEncryptedMSG = Base64.getDecoder().decode(MSG.getBytes("UTF-8"));
    	decryptedMSG = c.doFinal(byteEncryptedMSG);
    	
    	MSG = new String(decryptedMSG,"UTF-8");
        
    	//복호화된 msg를 string으로 반환
    	return MSG;
    }
	/*
	 * Send thread (메시지 보내는 thread)
	 */   
    public static void SendThread()
    {
    	new Thread(new Runnable()
    			{
					@Override
					public void run() {
						try {
				    		Calendar now = null;		//현재 시각
				    		String MSG = null;
				    		String encryptedMSG = null;
				    		String timestamp = null;	//전달받은 timestamp
				    	
							while(recvTh)
							{
								System.out.print("> ");
					            MSG = send.readLine();    			//보낼 메세지 전송

					            now = Calendar.getInstance(Locale.KOREA);		
					            //timestamp 저장
					            timestamp = new String("[" + now.get ( Calendar.YEAR ) + "/" + (now.get ( Calendar.MONTH ) + 1 ) 
										+ "/" + now.get ( Calendar.DATE ) + " " + now.get ( Calendar.HOUR_OF_DAY )
										+ ":" + now.get ( Calendar.MINUTE ) + ":" + now.get ( Calendar.SECOND ) + "]");

					            encryptedMSG = MSG_encryption("\"" + MSG + "\" " + timestamp);	//보낼 메세지 + timestamp 암호화
					            out.println(encryptedMSG);
					            out.flush();                           //메시지 + timestamp  전송

					            System.out.println();
					            
					            if(MSG.equals("exit"))				//서버가 종료 요청
					            {
					            	sendTh = false;
					            	return;
					            }
							}
							return;
							
						}catch (InvalidKeyException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (UnsupportedEncodingException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (NoSuchAlgorithmException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (NoSuchPaddingException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (IllegalBlockSizeException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (BadPaddingException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (InvalidAlgorithmParameterException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}		
					}
    		
    			}).start();
    	
    }
    /*
	 * Recv thread (메시지 받는 thread)
	 */   
    public static void RecvThread()
    {
    	new Thread(new Runnable()
    			{

					@Override
					public void run() {
						Calendar now = null;
			    		String MSG = null;
			    		String encryptedMSG = null;
			    		String timestamp = null;	//전달받은 timestamp

			    		try {
						while(sendTh)
						{
				            encryptedMSG = in.readLine();                	//Client로부터 데이터를 읽어옴 
				            MSG = MSG_decryption(encryptedMSG);			//암호화된 MSG 복호화
				          
				            System.out.println("Received : " + MSG);
				            System.out.println("Encrypted Message : \"" + encryptedMSG + "\"");
				            
				            if(MSG.contains("\"exit\" "))					//client가 종료 요청
				            {
				            	recvTh = false;

				            	now = Calendar.getInstance(Locale.KOREA);		
				            	//timestamp 저장			                
				    			 timestamp = new String("[" + now.get ( Calendar.YEAR ) + "/" + (now.get ( Calendar.MONTH ) + 1 ) 
											+ "/" + now.get ( Calendar.DATE ) + " " + now.get ( Calendar.HOUR_OF_DAY )
											+ ":" + now.get ( Calendar.MINUTE ) + ":" + now.get ( Calendar.SECOND ) + "]");
				    			
				    			encryptedMSG = MSG_encryption("\"exit\" " + timestamp); //cliet가 exit 암호화
				    			
				                out.println(encryptedMSG);                        //서버로 메세지전송
				                out.flush();
				                
				                Thread.sleep(1000);
				                
				            	socket.close(); 			//socket close
				            	System.out.println("Connection closed.");
				            	server_socket.close(); 		//server socket close
				                sendTh = false;
				            	System.exit(0);			//모든 system 종료	
				            }
				            
				            System.out.println();
				            System.out.print("> ");
							
						}
						
	
						
			    		} catch (InvalidKeyException e) {
			    			// TODO Auto-generated catch block
			    			e.printStackTrace();
			    		} catch (UnsupportedEncodingException e) {
			    			// TODO Auto-generated catch block
			    			e.printStackTrace();
			    		} catch (NoSuchAlgorithmException e) {
			    			// TODO Auto-generated catch block
			    			e.printStackTrace();
			    		} catch (NoSuchPaddingException e) {
			    			// TODO Auto-generated catch block
			    			e.printStackTrace();
			    		} catch (IllegalBlockSizeException e) {
			    			// TODO Auto-generated catch block
			    			e.printStackTrace();
			    		} catch (BadPaddingException e) {
			    			// TODO Auto-generated catch block
			    			e.printStackTrace();
			    		} catch (InvalidAlgorithmParameterException e) {
			    			// TODO Auto-generated catch block
			    			e.printStackTrace();
			    		} catch (IOException e) {
			    			// TODO Auto-generated catch block
			    			e.printStackTrace();
			    		} catch (InterruptedException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}		
					}
    		
    			}).start();
    	
    }
    
}
