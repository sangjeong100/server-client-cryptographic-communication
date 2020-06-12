//Socket ��� import
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
	
	public static Socket socket = null;            //Server�� ����ϱ� ���� Socket
    public static BufferedReader in = null;        //Server�κ��� �����͸� �о���̱� ���� �Է½�Ʈ��
    public static BufferedReader send = null;        //Ű����κ��� �о���̱� ���� �Է½�Ʈ��
    public static PrintWriter out = null;            //������ �������� ���� ��� ��Ʈ��
	private static String AES_key = null; 		//AES ���Ű
	private static String iv_str= null; //�ʱ⺤��
    public static boolean sendTh; 
    public static boolean recvTh;
    
    
	public static void main(String arg[])
    {

        InetAddress ia = null;
        try {
            ia = InetAddress.getByName("127.0.0.1");    //���� IP����
            socket = new Socket(ia,4000);				//������ �����û

            in = new BufferedReader(new InputStreamReader(socket.getInputStream())); //socket�Է½�Ʈ�� ����
            send = new BufferedReader(new InputStreamReader(System.in));				//Ű���� �Է½�Ʈ�� ����
            out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))); //socket��½�Ʈ�� ����
            
      
        }catch(IOException e) {				
        	System.out.println(e.getMessage());
        	return;
        }
        
        try {
		    //RSA ����Ű ����
		    String RSA_pubkey = in.readLine();
		    System.out.println(">Received Public Key : " + RSA_pubkey);
		   		    
		    //AES key �����Լ�
		    CreateAES_key();		    
		 
		    String encrypted_AES_Key = encryptRSA(AES_key, RSA_pubkey);
		    String encrypted_iv = encryptRSA(iv_str,RSA_pubkey);
		    //AES Key ,�ʱ⺤�� ��ȣȭ �Ϸ�
		    
		    System.out.println("AES 256 key : "+AES_key);
		    System.out.println("IV : "+iv_str);
		    System.out.println("Encrypted AES Key : "+encrypted_AES_Key );
		    System.out.println("Encrypted IV : "+ encrypted_iv + "\n");
		    
		    out.println(encrypted_AES_Key);
		    out.flush();		    
		    out.println(encrypted_iv);
		    out.flush();
		    //RSA�� ��ȣȭ�� AES key�� �ʱ⺤��  ����

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
	
	//ä�� ��ƾ �Լ�
	static void secure_chating() 
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		recvTh = true;
		sendTh = true;   
		//thread ���� ��, thread ��� ������ �����

		
    	SendThread();	//send thread
    	RecvThread();	//receive thread
    	
    	while(sendTh || recvTh);		//send thread�� recv thread ���������� spin lock
    	
	}
	
	/*RSA��ȣȭ �Լ� (AES key ��ȣȭ)
	���޹��� string����Ű�� Public key��ü�� �ٲٰ�
	AES�� Ű�� �ʱ⺤�͸�  ����Ű�� ��ȣȭ
	*/
	private static String encryptRSA(String data, String stringPublicKey) 
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, UnsupportedEncodingException {
        
        //���޹��� ����Ű�� ����Ű��ü�� ����� ����
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] bytePublicKey = Base64.getDecoder().decode(stringPublicKey.getBytes("UTF-8"));
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytePublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		
        //������� ����Ű��ü�� ������� ��ȣȭ�ϴ� ����
		Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] Byte_data = cipher.doFinal(data.getBytes("UTF-8"));
        String encrypted_data = new String(Base64.getEncoder().encode(Byte_data),"UTF-8");
        
    	return encrypted_data; //RSA ����Ű�� �̿��� ��ȣȭ �Ϸ�
    }
	
	private static void CreateIV() throws NoSuchAlgorithmException, UnsupportedEncodingException
	{
		byte[] iv = new byte[16];
	 	SecureRandom Randomkey = SecureRandom.getInstance("SHA1PRNG");
	 	Randomkey.nextBytes(iv);
	 	iv_str = new String(Base64.getEncoder().encode(iv),"UTF-8");
	}

	/*
	 * AES 256bit ���Ű ���� �Լ�
	 */
	 private static void CreateAES_key() throws InvalidKeyException, NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException 
	 {	
			 System.out.println("Creating AES 256 Key��");
			 //256bit�� random ���Ű ����
			 KeyGenerator gen = KeyGenerator.getInstance("AES");
			 SecureRandom Randomkey = SecureRandom.getInstance("SHA1PRNG");	//SHA1���� ���� Ű ���� 
			 gen.init(256, Randomkey);
			 
			 SecretKey secretkey = gen.generateKey();
			 AES_key = new String(Base64.getEncoder().encode(secretkey.getEncoded()),"UTF-8");
	        
			 CreateIV();
	 }
	 
	/*
	 * MSG�� AES�� ��ȣȭ�ϴ� �Լ� 
	 */
    private static String Msg_encryption(String MSG) 
    		throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException
    {
    	byte[] iv=Base64.getDecoder().decode(iv_str.getBytes("UTF-8"));				//�ʱ� ���� 
    	byte[] Byte_AES_key = Base64.getDecoder().decode(AES_key.getBytes("UTF-8"));//AES key
    	   	
    	//AES��ȣ��� CBC �� PKCS5 padding ���� ,�ʱ� ���� ���� 
		SecretKeySpec secretkeySpec = new SecretKeySpec(Byte_AES_key,"AES");
		Cipher c =  Cipher.getInstance("AES/CBC/PKCS5Padding");
    	IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		c.init(Cipher.ENCRYPT_MODE,secretkeySpec, ivParameterSpec);

    	//AES key�� msg��ȣȭ
		byte[] encryptedMSG = c.doFinal(MSG.getBytes("UTF-8"));
		MSG = new String(Base64.getEncoder().encode(encryptedMSG),"UTF-8");
	
	   return MSG;		//��ȣȭ�� msg string���� ��ȯ
    }	 

	/*
	 * ���� MSG�� AES�� ��ȣȭ�ϴ� �Լ� 
	*/
    private static String MSG_decryption(String MSG) 
    		throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
    	
    	byte[] iv= Base64.getDecoder().decode(iv_str.getBytes("UTF-8"));			//�ʱ� ���� 
    	byte[] Byte_AES_key = Base64.getDecoder().decode(AES_key.getBytes("UTF-8"));//AES key
    	
    	//AES��ȣȭ��� CBC �� PKCS5 �е� ���� ���� , �ʱ� ���� ����
    	SecretKeySpec secretkeySpec = new SecretKeySpec(Byte_AES_key,"AES");    	
    	Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

    	c.init(Cipher.DECRYPT_MODE, secretkeySpec,ivParameterSpec );
    	
    	//��ȣȭ ���� , UTF-8 ���
    	byte[] byteEncryptedMSG = Base64.getDecoder().decode(MSG.getBytes("UTF-8"));
    	byte[] decryptedMSG = c.doFinal(byteEncryptedMSG);
        
    	MSG = new String(decryptedMSG,"UTF-8");
        
    	//��ȣȭ�� msg�� string���� ��ȯ
    	return MSG;
    }

	/*
	 * send thread (�޽��� ������ thread)
	 */   
    public static void SendThread()
    {
    	new Thread(new Runnable()
    			{
					
					@Override
					public void run() {
						try {
				    		Calendar now = null;		//���� �ð�
				    		String MSG = null;
				    		String encryptedMSG = null;
				    		String timestamp = null;	//���޹��� timestamp

							while(recvTh)
							{
								System.out.print("> ");
					            MSG = send.readLine();    			//���� �޼��� ����

					            now = Calendar.getInstance(Locale.KOREA);		
					            //timestamp ����
					            timestamp = new String("[" + now.get ( Calendar.YEAR ) + "/" + (now.get ( Calendar.MONTH ) + 1 ) 
										+ "/" + now.get ( Calendar.DATE ) + " " + now.get ( Calendar.HOUR_OF_DAY )
										+ ":" + now.get ( Calendar.MINUTE ) + ":" + now.get ( Calendar.SECOND ) + "]");
					            
					  
					            encryptedMSG = Msg_encryption("\"" + MSG + "\" " + timestamp);	//���� �޼��� + timestamp ��ȣȭ
					            out.println(encryptedMSG);
					            out.flush();                           //�޽��� +timestamp  ����

					            System.out.println();
					            
					            if(MSG.equals("exit"))				//������ ���� ��û
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
	 * Recv thread (�޽��� �޴� thread)
	 */   
    public static void RecvThread()
    {
    	new Thread(new Runnable()
    			{

					@Override
					public void run() {
			    		Calendar now = null;		//���� �ð�
			    		String MSG = null;
			    		String encryptedMSG = null;
			    		String timestamp = null;	//���޹��� timestamp
			    		
			    		try {
						while(sendTh)
						{

				            encryptedMSG = in.readLine();                	//server�κ��� �����͸� �о��
				            
				            MSG = MSG_decryption(encryptedMSG);			//��ȣȭ�� MSG ��ȣȭ
				            
				            System.out.println("Received : " + MSG);
				            System.out.println("Encrypted Message : \"" + encryptedMSG + "\"");
				           
				            
				            if(MSG.contains("\"exit\" "))					//client�� ���� ��û 
				            {												//MSG�� "exit" �����ϴ��� Ȯ��
				            	recvTh = false;            	
				    			
				    			now = Calendar.getInstance(Locale.KOREA);		
				    			//timestamp ����
				    			timestamp = new String("[" + now.get ( Calendar.YEAR ) + "/" + (now.get ( Calendar.MONTH ) + 1 ) 
				    					+ "/" + now.get ( Calendar.DATE ) + " " + now.get ( Calendar.HOUR_OF_DAY )
				    					+ ":" + now.get ( Calendar.MINUTE ) + ":" + now.get ( Calendar.SECOND ) + "]");

				    			encryptedMSG = Msg_encryption("\"exit\" " + timestamp); //cliet�� exit + timestamp ��ȣȭ
				    			
				                out.println(encryptedMSG);                        //������ �޼�������
				                out.flush();
				                
				                sendTh = false;
				                
				                
								Thread.sleep(1000);
								                
				            	socket.close(); 			//socket close
				            	System.out.println("Connection closed.");
				            	
				            	System.exit(0);						//��� system ����
				                
				                
				            	return;
				            	
				            	
				            }
				            System.out.println();
				            System.out.print("> ");
							
						}
						
						encryptedMSG = in.readLine();                	//Client�κ��� �����͸� �о��
			            
			            MSG = MSG_decryption(encryptedMSG);			//��ȣȭ�� MSG ��ȣȭ
			            
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