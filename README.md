# server-client-cryptographic-communication
server client socket 암호화 통신입니다.
수행 환경은 local입니다.

### 환경

> 사용 언어 : java

> 사용 IDE : Eclipse

### 기능
- Server - Client간의 채팅 기능
  - Socket 통신
  - Send Thread, Recieve Thread 구현
  - BufferedReader, PrintWriter 사용
  
- RSA 암호화 이용한 키 교환
  - Server에서 1024bit의 랜덤 키쌍 생성
  - Server가 Client에게  Public Key 전달
  - Client가 256 bit의 AES key 생성 후, server의 public key로 암호화
  - Client가 암호화된 AES key를 Server에게 전달
  - Server가 암호화된 AES key를 private key로 복호화
  
- AES 암호화 이용한 채팅
  - AES를 통한 암/복호화 채팅 구현
  - CBC 모드 사용
  - PKCS5Padding 모드 사용
 
 ------------------------------------------ 
 ###참고

[Java에서의 server, client 통신 참조](https://lktprogrammer.tistory.com/62)

[RSA 암/복호화 참조](https://offbyone.tistory.com/346)

[PublicKey, PrivateKey 객체를 string형으로 바꾸는 방법 참조](https://this-programmer.com/entry/Java%EC%9E%90%EB%B0%94Spring%EC%8A%A4%ED%94%84%EB%A7%81-RSA-%EA%B3%B5%EA%B0%9C%ED%82%A4-%EA%B0%9C%EC%9D%B8%ED%82%A4-%EC%95%94%ED%98%B8%ED%99%94-%EB%B0%A9%EC%8B%9D%EC%9D%84-String%ED%98%95%ED%83%9C%EB%A1%9C-%EB%8B%A4%EB%A4%84%EB%B3%B4%EC%9E%90)

[java의 AES 암/복호화 참조](http://blog.naver.com/PostView.nhn?blogId=wpdus2694&logNo=220898932452&redirect=Dlog&widgetTypeCall=true)

[base64 인코딩, 디코딩 참조](https://dev-syhy.tistory.com/15)

[java에서 thread 사용한 채팅 예제 참조](https://blog.naver.com/PostView.nhn?blogId=ilikebigmac&logNo=221587381568)

 
 
