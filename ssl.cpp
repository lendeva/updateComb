#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>

#include <string>
#include <sstream>

#include <sqlite3.h>
#include <regex>
#include <random>
#include <vector>

#include <pthread.h>
#include <thread>

#include <mutex>
#include <typeinfo>
#include <time.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <chrono>
#include <ctime>
#include <signal.h>

#define BUFSIZZ 4048


const int PORT = 443;
const char* CERT_FILE = "/etc/ssl/certs/selfsigned.crt";
const char* KEY_FILE = "/etc/ssl/private/selfsigned.key";
 SSL_CTX* ctx;
struct newClient{
	std::string cookie;
	int timeout;
};

std::vector <newClient> clients; // вектор из структур
/*
	for (auto it = vex.begin(); it!=vec.end(); ++it){
		if (*it == cookie_m[1]){
			cookies.erase(it);
			found_elem = true;
			break;
		}
	}

	if (found_elem){
		std::cout<<"was removed\n";
	}
*/



pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

std::regex regex_get ("GET / HTTP/|GET /login HTTP/");
std::regex regex_post ("POST /login HTTP/");
std::regex regular_exp("username=(.*)(?=&)&password=(.*)(?=&|$)");
std::regex regex_cookie ("userID=(.*)");
std::regex regex_mobile ("User-Agent: (.*)Android");

//std::string keep = "Connection: keep-alive";

std::smatch m_cookie;
std::smatch m_app;

// initialization ssl
void init_ssl(){
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

//create context ssl
SSL_CTX* create_context(const char* key_file, const char* crt_file) {
    
   // создание SSL контекста
    SSL_CTX* ctx = SSL_CTX_new (TLS_server_method());


    if (ctx == NULL) { // обработка ошибки
        std::cerr << "Error creating SSL context\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (SSL_CTX_use_certificate_file(ctx, crt_file, SSL_FILETYPE_PEM) <= 0) {
    	printf("NO crt file");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        printf("NO key file");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

int create_Serversocket(int port){
    int s; // descriptor
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
    
    
    if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        std::cerr << "Error binding socket\n";
        exit(EXIT_FAILURE);
    }


    if (listen(s, 5) < 0) {
        std::cerr << "Error listening on socket\n";
        exit(EXIT_FAILURE);
    }
    
    return s;
}


sqlite3* openDatabase(){
	sqlite3* DB;
	int resultOpenDB = 0;
   	std::string sql;
	
    
    	resultOpenDB = sqlite3_open("basa.db", &DB);
    	
    	if (resultOpenDB){
   	//	 printf("Can not open database");
    
   	} else {
    	//	std::cout<<"Opened database"<<std::endl;
    	}
    	//std::cout<<"DB = "<<DB<<std::endl;
    	return DB;
}

int callback (void* data, int argc, char** argv, char** azColName){
	//std::cout<<"argv[0] = "<<argv[0]<<std::endl;
	return atoi(argv[0]);
}

int AutorizationQuery (std::string &username, std::string &password){
	char* messageError = 0;
	std::string sql = "SELECT EXISTS (SELECT * FROM Users WHERE Login = \"" + username + "\" AND Password = \""+password+"\")";
	//std::cout<<sql<<std::endl;
	sqlite3* DB = openDatabase();
	sqlite3_stmt *res;
	int rAutorazation = sqlite3_exec(DB, sql.c_str(), callback, 0, &messageError);
	std::cout<<"rAutorazation"<<rAutorazation<<std::endl;
	
	if(rAutorazation == SQLITE_OK){
		//std::cerr<<"Error not such user"<<std::endl;
		return 1;
	
	} else {
	
		//std::cout<<"rAutorazation Ok!"<<std::endl;
		return 0;
	}

}



int callback1 (void* data, int argc, char** argv, char** azColName){
	return atoi(argv[0]);
}


int getStatus (std::string &username, std::string &password){
	char* messageError = 0;
	std::string sql = "SELECT EXISTS (SELECT * FROM Users WHERE Login = \'" + username + "\' AND Password = \'"+password+"\' AND Status = \'admin\')";
	std::cout<< sql<<std::endl;
	//std::cout<<sql<<std::endl;
	sqlite3* DB = openDatabase();
	sqlite3_stmt *res;
	int rStatus = sqlite3_exec(DB, sql.c_str(), callback1, 0, &messageError);
	std::cout<<"rStatus"<<rStatus<<std::endl;
	
	if(rStatus == SQLITE_OK){
		//std::cerr<<"Error not such user"<<std::endl;
		return 1;
	
	} else {
	
		//std::cout<<"rAutorazation Ok!"<<std::endl;
		return 0;
	}

}




//int checkOpenLoginForm(std::ifstream html_file){
//	return 0;
//}

void mesProcesing(char* buf_read, SSL* ssl){//обработка сообщения

	std::ifstream html_file("login.html");
	if(!html_file.is_open()){
		std::cerr<<"Error opening HTML file\n";
		exit(EXIT_FAILURE);
	}
	std::stringstream buffer_html;
	buffer_html<< html_file.rdbuf();
	std::string bufReadStr(buf_read);
	std::string html_content = buffer_html.str();

	std::string response;

	std::smatch m;
	std::string username, password, find_cookie;
	std::stringstream ss;
	int sessid;
	
	if ( std::regex_search(bufReadStr,m_app, regex_mobile) ){
		response = "HTTP/1.1 200 OK\nContent-Type text/html\r\nConnection: keep-alive\n\n<!DOCTYPE html><html><head><title>hello mobile</title><link rel=\"icon\" href=\"data:,\"></head><body bgcolor=\"white\"><center><h1>Hello mobile user</h1></center><hr><center>nginx/0.8.54</center></body></html>";
	
	}
	
	
	
	if (bufReadStr.find("Cookie") == std::string::npos){ // куки нет
		sessid = 1000+rand()%8999;
		ss << "Set-Cookie: userID="<<sessid;
		std::cout<<"sessid"<<sessid;
		pthread_mutex_lock(&mtx);
		newClient client;
		client.cookie = std::to_string(sessid);
		client.timeout = std::time(nullptr);
		clients.push_back(client);
		pthread_mutex_unlock(&mtx);
		
		std::cout<<"clients.size = " << clients.size()<<std::endl;
		std::cout<<"set-cookie to new"<<std::endl;
		std::cout<<"client.cookie"<<client.cookie<<std::endl;
		std::cout<<"client.timeout"<<client.timeout<<std::endl;
		

		
		
	}  			
	
	if (std::regex_search(bufReadStr,regex_get)){ // give login form
		response = "HTTP/1.1 200 OK\nContent-Type: text/html\r\n" + ss.str() + "\r\n\n " + html_content;
		
		
	} 
	//check username and password
	else if ( std::regex_search ( bufReadStr,regex_post ) ){
		if ( std::regex_search (bufReadStr,m, regular_exp ) ) {
			username = m[1];
			//std::cout<<"username = "<<username<<std::endl;
		
			password = m[2];
			//std::cout<<"password = "<<password<<std::endl;
			
			if(AutorizationQuery(username, password) == 0){
				
				//std::cout << "getStatus" << getStatus(username, password)<<std::endl;
				
				
				response = "HTTP/1.1 404 Not Found\nContent-Type text/html\r\n" + ss.str()+"\rnConnection: keep-alive\n\n<!DOCTYPE html><html><head><title>Hello</title><link rel=\"icon\" href=\"data:,\"></head><body bgcolor=\"white\"><center><h1>Hello, "+username + "</h1></center><hr><center>nginx/0.8.54</center></body></html>";
			
			} else {
				response = "HTTP/1.1 404 Not Found\nContent-Type text/html\r\nConnection: keep-alive\n\n<!DOCTYPE html><html><head><title>sorry</title><link rel=\"icon\" href=\"data:,\"></head><body bgcolor=\"white\"><center><h1>Sorry</h1></center><hr><center>nginx/0.8.54</center></body></html>";
			
			}
		
		}
	}
	else {
		response = "HTTP/1.1 404 Not Found\nContent-Type text/html\nContent-Length: 169\nConnection:keep_alive\nConnection: keep-alive\n\n<!DOCTYPE html><html><head><title>404 Not Found</title><link rel=\"icon\" href=\"data:,\"></head><body bgcolor=\"white\"><center><h1>404 Not Found</h1></center><hr><center>nginx/0.8.54</center></body></html>";
		
		
	
	}
	
	SSL_write(ssl, response.c_str(), response.size());

	if (std::regex_search(bufReadStr, m_cookie, regex_cookie)){
		std::cout<<"m_cookie[1]"<<std::endl;
		bool flag = false;
		
		for (auto& elem : clients){
			if (elem.cookie == m_cookie[1]){
				std::cout<<"update time\n"<<std::endl;
				pthread_mutex_lock(&mtx);
				elem.timeout = std::time(nullptr); 
				pthread_mutex_unlock(&mtx);
				flag = true;
			} 
		
		} if (flag == false ){ // cookie is not in vector
			pthread_mutex_lock(&mtx);
			newClient client;
			client.cookie = m_cookie[1];
			client.timeout = std::time(nullptr);
			clients.push_back(client);
			pthread_mutex_unlock(&mtx);
			std::cout<<"clients.size = " << clients.size()<<std::endl;
			std::cout<<"set-cookie to old"<<std::endl;
			std::cout<<"client.cookie"<<client.cookie<<std::endl;
			std::cout<<"client.timeout"<<client.timeout<<std::endl;
		}
	
	
	}

// обновить время последней активности



} 


void* clientHandling (void* s){
	
	int clientSock = *((int*)s);
	free(s);
	int r = 0;
	int count = 0;
	int bytesRead;
	char buf_read[BUFSIZZ];
	SSL* ssl;
	
	ssl = SSL_new(ctx);

	if (ssl == nullptr){ // обработка ошибки
  		std::cout<<"ssl handshake error\n";
        }
        else {	
		SSL_set_fd(ssl, clientSock);
		r = SSL_accept(ssl); // ?? SSL_connect
		if (r <= 0) { // обработка ошибки
		    printf ("SSL accept error");
		    int er = SSL_get_error(ssl, r);
		    close(clientSock);
		   // continue;
		    exit(EXIT_FAILURE);
		}
		
		if (SSL_read(ssl, buf_read, sizeof(buf_read)) > 0){
			std::cout<<"Read SSLdata: "<<buf_read<<std::endl;
			mesProcesing(buf_read, ssl);
			bzero (buf_read, BUFSIZZ - 1);
		} else std::cout<<"NO DATA FROM CLIENT!\n";
							
		SSL_shutdown(ssl); // закрывать ssl по истечении таймера
	    	SSL_free(ssl);
	    	
    	}
    	
    	close(clientSock);
    	pthread_exit(NULL);
    	return NULL;
}




int clientAccept (int servSock, SSL_CTX* ctx){
	
	int s;
    	while (true) {
		struct sockaddr_in client_addr;
		socklen_t socklen = sizeof(client_addr);
		s = accept(servSock, (struct sockaddr*)&client_addr, &socklen);

		if (s < 0) {
		    std::cerr << "Error accepting connection\n";
		    exit(EXIT_FAILURE);
		}
		
		std::cout<<"Address : "<<inet_ntoa(client_addr.sin_addr)<<std::endl;
		std::cout<<"Port : "<<(int)ntohs(client_addr.sin_port)<<std::endl;

		pthread_t p;
		int *pSocket =(int*)malloc(sizeof(int));
		*pSocket = s;
		

		if (pthread_create (&p, NULL, clientHandling, pSocket) != 0) {
		
			std::cout<<"error pthread_create\n";
		};
		pthread_detach(p);
	}
	
	return s;
}
        


void* checkTimeoutofClients(void* arg){
	while(1){
		if (!clients.empty()){
			for (auto it = clients.begin(); it != clients.end();){
				std::time_t currentTime = std::time(nullptr);
				if (difftime(currentTime, it->timeout) > 30){
					std::cout<<"need to delete\n";
					it = clients.erase(it);
					std::cout<<"clients.size = "<<clients.size()<<std::endl;
				} else {
					++it;
				}
			}

			//for (const auto& elem : clients){
			//	std::cout<<"data: "<< elem.data <<" and time: "<<elem.time<<std::endl; 
			//}
			sleep(5);
		}
			
		else sleep(5);	
	}
}
  
int main() {
	int servSock;
	sqlite3 *DB = openDatabase();
	//if (checkOpenLoginForm(html_file) != 0){
	//	std::cout<<"error open login form"<<std::endl;
	//	return 1;
	//};
	
	init_ssl();
	ctx = create_context(KEY_FILE, CERT_FILE);
	servSock = create_Serversocket(PORT);
	
	
	pthread_t pDel;
	if (pthread_create (&pDel, NULL, checkTimeoutofClients, nullptr) != 0){
		std::cout<<"pDel is not created!"<<std::endl;
	}
	
	clientAccept(servSock, ctx);
	
	SSL_CTX_free(ctx); // освобождаем ресурсы
	sqlite3_close(DB);
	return 0;
}

    
    
    
    //fd_set readableSet = readSet;
			//struct timeval tv;// таймаут на чтение данных из сокета
			//tv.tv_sec = 10;
			//tv.tv_usec = 0;
			//int readySockets = select(FD_SETSIZE, &readableSet, nullptr, nullptr, &tv);
			//if (readySockets == -1) {
			//	std::cout<<"error111\n";
			//} else if (readySockets == 0) {
			//	std::cout<<"timeout\n";
			//	continue;
			//}
			/*
			if (FD_ISSET(clientSock, &readableSet)){
				char buf_read[BUFSIZZ];
				int bytesRead = SSL_read( ssl, buf_read, sizeof( buf_read )) ;
				int count;
				ioctl (clientSock, FIONREAD, &count);
				std::cout<<"count" << count<<std::endl;
					if ( bytesRead > 0 ){
						std::cout<<"buffer"<<buf_read<<std::endl;
						// обработка полученных данных
						std::cout<<"Read ssldata: "<<buf_read<<std::endl;
						mesProcesing(buf_read, ssl);
						std::cout<<"3\n";
						bzero(buf_read, BUFSIZZ-1);
						//memset(buf_read, 0, sizeof(buf_read));
					} else if (bytesRead == 0 ) {
						std::cout<<"client disconnected\n";
						break;
							
					} else if (bytesRead == -1 ){
						std::cout<<"error read data\n";
						break;
					}
				
			}
			*/






