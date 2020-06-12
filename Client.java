//Socket 통신 import
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
//RSA,AES import
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.*;
import java.security.*;
import java.util.Base64;
//timestamp import
import java.util.Calendar;
import java.util.Locale;

public class Client {
	
	public static Socket socket = null;            //Server와 통신하기 위한 Socket
    public static BufferedReader in = null;        //Server로부터 데이터를 읽어들이기 위한 입력스트림
    public static BufferedReader send = null;        //키보드로부터 읽어들이기 위한 입력스트림
    public static PrintWriter out = null;            //서버로 내보내기 위한 출력 스트림
	private static String AES_key = null; 		//AES 비밀키
	private static String iv_str= null; //초기벡터
    public static boolean sendTh; 
    public static boolean recvTh;
    
    
	public static void main(String arg[])
    {

        InetAddress ia = null;
        try {
            ia = InetAddress.getByName("127.0.0.1");    //서버 IP지정
            socket = new Socket(ia,4000);				//서버에 연결요청

            in = new BufferedReader(new InputStreamReader(socket.getInputStream())); //socket입력스트림 생성
            send = new BufferedReader(new InputStreamReader(System.in));				//키보드 입력스트림 생성
            out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))); //socket출력스트림 생성
            
      
        }catch(IOException e) {				
        	System.out.println(e.getMessage());
        	return;
        }
        
        try {
		    //RSA 공개키 받음
		    String RSA_pubkey = in.readLine();
		    System.out.println(">Received Public Key : " + RSA_pubkey);
		   		    
		    //AES key 생성함수
		    CreateAES_key();		    
		 
		    String encrypted_AES_Key = encryptRSA(AES_key, RSA_pubkey);
		    String encrypted_iv = encryptRSA(iv_str,RSA_pubkey);
		    //AES Key ,초기벡터 암호화 완료
		    
		    System.out.println("AES 256 key : "+AES_key);
		    System.out.println("IV : "+iv_str);
		    System.out.println("Encrypted AES Key : "+encrypted_AES_Key );
		    System.out.println("Encrypted IV : "+ encrypted_iv + "\n");
		    
		    out.println(encrypted_AES_Key);
		    out.flush();		    
		    out.println(encrypted_iv);
		    out.flush();
		    //RSA로 암호화된 AES key와 초기벡터  전송

            secure_chating();
		    
        }catch(IOException e) {
        	System.out.println(e.getMessage());
        	return;
        } catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
	
	//채팅 루틴 함수
	static void secure_chating() 
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		recvTh = true;
		sendTh = true;   
		//thread 시작 전, thread 살아 있음을 명시함

		
    	SendThread();	//send thread
    	RecvThread();	//receive thread
    	
    	while(sendTh || recvTh);		//send thread와 recv thread 끝날떄까지 spin lock
    	
	}
	
	/*RSA암호화 함수 (AES key 암호화)
	전달받은 string공개키를 Public key객체로 바꾸고
	AES의 키와 초기벡터를  공개키로 암호화
	*/
	private static String encryptRSA(String data, String stringPublicKey) 
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, UnsupportedEncodingException {
        
        //전달받은 공개키를 공개키객체로 만드는 과정
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] bytePublicKey = Base64.getDecoder().decode(stringPublicKey.getBytes("UTF-8"));
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytePublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		
        //만들어진 공개키객체를 기반으로 암호화하는 과정
		Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] Byte_data = cipher.doFinal(data.getBytes("UTF-8"));
        String encrypted_data = new String(Base64.getEncoder().encode(Byte_data),"UTF-8");
        
    	return encrypted_data; //RSA 공개키를 이용한 암호화 완료
    }
	
	private static void CreateIV() throws NoSuchAlgorithmException, UnsupportedEncodingException
	{
		byte[] iv = new byte[16];
	 	SecureRandom Randomkey = SecureRandom.getInstance("SHA1PRNG");
	 	Randomkey.nextBytes(iv);
	 	iv_str = new String(Base64.getEncoder().encode(iv),"UTF-8");
	}

	/*
	 * AES 256bit 비밀키 생성 함수
	 */
	 private static void CreateAES_key() throws InvalidKeyException, NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException 
	 {	
			 System.out.println("Creating AES 256 Key…");
			 //256bit의 random 비밀키 생성
			 KeyGenerator gen = KeyGenerator.getInstance("AES");
			 SecureRandom Randomkey = SecureRandom.getInstance("SHA1PRNG");	//SHA1으로 랜덤 키 생성 
			 gen.init(256, Randomkey);
			 
			 SecretKey secretkey = gen.generateKey();
			 AES_key = new String(Base64.getEncoder().encode(secretkey.getEncoded()),"UTF-8");
	        
			 CreateIV();
	 }
	 
	/*
	 * MSG를 AES로 암호화하는 함수 
	 */
    private static String Msg_encryption(String MSG) 
    		throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException
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
	
	   return MSG;		//암호화된 msg string으로 반환
    }	 

	/*
	 * 받은 MSG를 AES로 복호화하는 함수 
	*/
    private static String MSG_decryption(String MSG) 
    		throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
    	
    	byte[] iv= Base64.getDecoder().decode(iv_str.getBytes("UTF-8"));			//초기 벡터 
    	byte[] Byte_AES_key = Base64.getDecoder().decode(AES_key.getBytes("UTF-8"));//AES key
    	
    	//AES복호화모드 CBC 및 PKCS5 패딩 설정 설정 , 초기 벡터 설정
    	SecretKeySpec secretkeySpec = new SecretKeySpec(Byte_AES_key,"AES");    	
    	Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

    	c.init(Cipher.DECRYPT_MODE, secretkeySpec,ivParameterSpec );
    	
    	//복호화 수행 , UTF-8 사용
    	byte[] byteEncryptedMSG = Base64.getDecoder().decode(MSG.getBytes("UTF-8"));
    	byte[] decryptedMSG = c.doFinal(byteEncryptedMSG);
        
    	MSG = new String(decryptedMSG,"UTF-8");
        
    	//복호화된 msg를 string으로 반환
    	return MSG;
    }

	/*
	 * send thread (메시지 보내는 thread)
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
					            
					  
					            encryptedMSG = Msg_encryption("\"" + MSG + "\" " + timestamp);	//보낼 메세지 + timestamp 암호화
					            out.println(encryptedMSG);
					            out.flush();                           //메시지 +timestamp  전송

					            System.out.println();
					            
					            if(MSG.equals("exit"))				//서버가 종료 요청
					            {
					            	sendTh = false;
					            	return;
					            }
							
							}
								
						
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
			    		Calendar now = null;		//현재 시각
			    		String MSG = null;
			    		String encryptedMSG = null;
			    		String timestamp = null;	//전달받은 timestamp
			    		
			    		try {
						while(sendTh)
						{

				            encryptedMSG = in.readLine();                	//server로부터 데이터를 읽어옴
				            
				            MSG = MSG_decryption(encryptedMSG);			//암호화된 MSG 복호화
				            
				            System.out.println("Received : " + MSG);
				            System.out.println("Encrypted Message : \"" + encryptedMSG + "\"");
				           
				            
				            if(MSG.contains("\"exit\" "))					//client가 종료 요청 
				            {												//MSG가 "exit" 포함하는지 확인
				            	recvTh = false;            	
				    			
				    			now = Calendar.getInstance(Locale.KOREA);		
				    			//timestamp 저장
				    			timestamp = new String("[" + now.get ( Calendar.YEAR ) + "/" + (now.get ( Calendar.MONTH ) + 1 ) 
				    					+ "/" + now.get ( Calendar.DATE ) + " " + now.get ( Calendar.HOUR_OF_DAY )
				    					+ ":" + now.get ( Calendar.MINUTE ) + ":" + now.get ( Calendar.SECOND ) + "]");

				    			encryptedMSG = Msg_encryption("\"exit\" " + timestamp); //cliet가 exit + timestamp 암호화
				    			
				                out.println(encryptedMSG);                        //서버로 메세지전송
				                out.flush();
				                
				                sendTh = false;
				                
				                
								Thread.sleep(1000);
								                
				            	socket.close(); 			//socket close
				            	System.out.println("Connection closed.");
				            	
				            	System.exit(0);						//모든 system 종료
				                
				                
				            	return;
				            	
				            	
				            }
				            System.out.println();
				            System.out.print("> ");
							
						}
						
						encryptedMSG = in.readLine();                	//Client로부터 데이터를 읽어옴
			            
			            MSG = MSG_decryption(encryptedMSG);			//암호화된 MSG 복호화
			            
			            System.out.println("Received : " + MSG);
			            System.out.println("Encrypted Message : \"" + encryptedMSG + "\"");
			            
			            return;
						
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