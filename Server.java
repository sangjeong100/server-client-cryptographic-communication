package Server;

//Socket ��� import
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

    private static String AES_key = null; 		//AES ���Ű
    private static String iv_str=null; 			//�ʱ⺤��
    public static Socket socket = null;                //Client�� ����ϱ� ���� Socket
    public static ServerSocket server_socket = null;  //���� ������ ���� ServerSocket 
    public static BufferedReader in = null;            //Client�κ��� �����͸� �о���̱� ���� �Է½�Ʈ��
    public static BufferedReader send = null;			  //Ű����κ��� �о���̱� ���� �Է½�Ʈ��
    public static PrintWriter out = null;                //Client�� �����͸� �������� ���� ��� ��Ʈ��
    public static boolean sendTh; 
    public static boolean recvTh;
    
    public static void main(String arg[])
    {
        try{
            server_socket = new ServerSocket();			//Server Socket ����
            server_socket.bind(new InetSocketAddress("127.0.0.1", 4000)); 
            //Socket�� SocketAddress(IpAddress + Port) ���ε�
            
        }catch(IOException e)
        {
            System.out.println(e.getMessage());
            return;
        }
        try {
            
            socket = server_socket.accept();    //������ Client ���� ���
            
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));    //socket�Է½�Ʈ�� ����
            send = new BufferedReader(new InputStreamReader(System.in));					//Ű���� �Է½�Ʈ�� ����
            out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))); //socket��½�Ʈ�� ����
            

            KeyPair keypair = CreateRSA_Key();  //RSA Key ����
            String stringPublicKey = Base64.getEncoder().encodeToString(keypair.getPublic().getEncoded());
            String stringPrivateKey = Base64.getEncoder().encodeToString(keypair.getPrivate().getEncoded());
            //����Ű, ����Ű�� string������ ��ȯ
            
        	System.out.println("Private Key : "+ stringPrivateKey);
        	System.out.println("Public Key : "+ stringPublicKey + "\n");
        	//RSA ����Ű, ����Ű ���
            
            out.println(stringPublicKey);   //client���� ����Ű ����
            out.flush();
            
            String encryptedAES_key =  in.readLine();	//client�κ��� ��ȣȭ�� AES key����
            String encryptedIV = in.readLine();			//client�κ��� ��ȣȭ�� IV ����
            
            System.out.println(">Received AES Key : " + encryptedAES_key);
            System.out.println(">Received IV : " + encryptedIV);
            //���� AES key �� IV ���
            
            AES_key = decryptRSA(encryptedAES_key, keypair.getPrivate());
            System.out.println("Decrypted AES Key : " + AES_key);       
            iv_str = decryptRSA(encryptedIV, keypair.getPrivate());
            System.out.println("Decrypted IV : " + iv_str + "\n");
            //��ȣȭ�� AES key�� �ʱ� ���͸� ���
            
            
            secure_chating();  //ä�� ��ƾ
            
            
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
    
    
    //chating �Լ�
    public static void secure_chating() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
    {           
		recvTh = true;
		sendTh = true;   
		//thread ���� ��, thread ��� ������ �����
		
    	SendThread();	//send thread
    	RecvThread();	//receive thread
    	
    	while(sendTh || recvTh);		//send thread�� recv thread ���������� spin lock  
    }
    
    /*
     * RSA KEY �� ���� �Լ� 
     * server class �������� ���� �����ϵ��� Ű ���� �Լ��� private�� ����
    * 2048bit RSA Ű�� ���� 
    */
    	private static KeyPair CreateRSA_Key() throws NoSuchAlgorithmException{

    	
    	System.out.println(">Creating RSA Key Pair��");
    	
    	KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA"); //Ű ������ RSA������� ���� 
    	SecureRandom Randomkey = new SecureRandom(); //������ Ű ���� ��ü
    	
    	gen.initialize(2048, Randomkey); //key �����ڷ� 2048 bit�� RSA key ����
    	
    	KeyPair keypair = gen.genKeyPair();
    	
    	
    	return keypair; //Ű �� return
    }
    
    /*
     RSA��ȣȭ �Լ� (AES key ��ȣȭ)
      ��ȣȭ�� AES Ű�� RSA ����Ű�� ��ȣȭ 
     */  
    	private static String decryptRSA(String encrypted_data, PrivateKey privateKey) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        String decrypted_data = null;

            //������� ����Ű��ü�� ���, ��ȣȭ ����
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            //��ȣȭ�� AES key�� ��ȣȭ�ϴ� ���� . UTF-8���
            byte[] byteEncrypted_data = Base64.getDecoder().decode(encrypted_data.getBytes("UTF-8"));
            byte[] byteDecrypted_data = cipher.doFinal(byteEncrypted_data);
            decrypted_data = new String(byteDecrypted_data,"UTF-8");

        return decrypted_data;
    }    

	/*
	 * MSG�� AES�� ��ȣȭ�ϴ� �Լ� 
	 */
    	private static String MSG_encryption(String MSG)
    		throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
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
	
    	//��ȣȭ�� msg string���� ��ȯ
		return MSG;		
    	}
    	//
    	// MSG ��ȣȭ �Լ�
    	// 
    	private static String MSG_decryption(String MSG) 
    		throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    	
    	byte[] decryptedMSG = null;
    	byte[] iv=Base64.getDecoder().decode(iv_str.getBytes("UTF-8"));			//�ʱ� ���� ����
    	byte[] Byte_AES_key = Base64.getDecoder().decode(AES_key.getBytes("UTF-8"));
    	
    	//AES��ȣȭ��� CBC �� PKCS5 �е� ���� ,�ʱ� ���� ���� 
    	SecretKeySpec secretkeySpec = new SecretKeySpec(Byte_AES_key,"AES");    	
    	Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
    	
    	c.init(Cipher.DECRYPT_MODE, secretkeySpec, ivParameterSpec);

    	//��ȣȭ ���� , UTF-8 ���
    	byte[] byteEncryptedMSG = Base64.getDecoder().decode(MSG.getBytes("UTF-8"));
    	decryptedMSG = c.doFinal(byteEncryptedMSG);
    	
    	MSG = new String(decryptedMSG,"UTF-8");
        
    	//��ȣȭ�� msg�� string���� ��ȯ
    	return MSG;
    }
	/*
	 * Send thread (�޽��� ������ thread)
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

					            encryptedMSG = MSG_encryption("\"" + MSG + "\" " + timestamp);	//���� �޼��� + timestamp ��ȣȭ
					            out.println(encryptedMSG);
					            out.flush();                           //�޽��� + timestamp  ����

					            System.out.println();
					            
					            if(MSG.equals("exit"))				//������ ���� ��û
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
	 * Recv thread (�޽��� �޴� thread)
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
			    		String timestamp = null;	//���޹��� timestamp

			    		try {
						while(sendTh)
						{
				            encryptedMSG = in.readLine();                	//Client�κ��� �����͸� �о�� 
				            MSG = MSG_decryption(encryptedMSG);			//��ȣȭ�� MSG ��ȣȭ
				          
				            System.out.println("Received : " + MSG);
				            System.out.println("Encrypted Message : \"" + encryptedMSG + "\"");
				            
				            if(MSG.contains("\"exit\" "))					//client�� ���� ��û
				            {
				            	recvTh = false;

				            	now = Calendar.getInstance(Locale.KOREA);		
				            	//timestamp ����			                
				    			 timestamp = new String("[" + now.get ( Calendar.YEAR ) + "/" + (now.get ( Calendar.MONTH ) + 1 ) 
											+ "/" + now.get ( Calendar.DATE ) + " " + now.get ( Calendar.HOUR_OF_DAY )
											+ ":" + now.get ( Calendar.MINUTE ) + ":" + now.get ( Calendar.SECOND ) + "]");
				    			
				    			encryptedMSG = MSG_encryption("\"exit\" " + timestamp); //cliet�� exit ��ȣȭ
				    			
				                out.println(encryptedMSG);                        //������ �޼�������
				                out.flush();
				                
				                Thread.sleep(1000);
				                
				            	socket.close(); 			//socket close
				            	System.out.println("Connection closed.");
				            	server_socket.close(); 		//server socket close
				                sendTh = false;
				            	System.exit(0);			//��� system ����	
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
