#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define DICT_FILE "words.txt"

/*
 * Task 4
 *
 * Given a plaintext and a ciphertext, find the key used to encrypt.
 * aes-128-cbc was used
 * key is an english word shorter than 16 characters, and ASCII space
 *  ' ' bits are appended to the key to form a 128 bit key
 * the IV is all 0.
 */

/*
 * For each word a list of potential words to try
 *  Turn the word into a valid key by appending spaces
 *  Use the key to encrypt the plaintext
 *  If the ciphertext matches the plaintext,
 *      return the word used
 *      break;
 */

/*
 * Task 5
 *
 *
 */

// from https://gist.github.com/xsleonard/7341172
// note: allocates its own memory
unsigned char* hexstr_to_char(const char* hexstr)
{
    size_t len = strlen(hexstr);
    if(len % 2 != 0)
        return NULL;
    size_t final_len = len / 2;
    unsigned char* chrs = (unsigned char*)malloc((final_len+1) * sizeof(*chrs));
    for (size_t i=0, j=0; j<final_len; i+=2, j++)
        chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;
    chrs[final_len] = '\0';
    return chrs;
}

/*
 * read in the dictionary
 */
int read_dict(char ***dict) {
    char **dictionary;
    char buf[17];
    char *tmp;
    unsigned long dict_length = 0;
    FILE *fp;
    fp = fopen(DICT_FILE, "r");
    if(fp == NULL) {
        printf("could not open" DICT_FILE "\n");
        return 1;
    }
    dictionary = (char **) malloc(sizeof(char *));
    while(fgets(buf, 17, fp) != NULL) {
        //append spaces if needed, then append to dict
        printf("read %lu bytes: \"%s\"\r", strlen(buf), buf);
        tmp = malloc(sizeof(char)* 17);
        strcpy(tmp, buf);
        memset(tmp + strlen(buf), ' ', 16-strlen(buf)); //pad with spaces
        memset(tmp + 16, '\0', 1); //null terminator
        dictionary = realloc(dictionary, (size_t) (dict_length + 1));
        dictionary[dict_length] = tmp;
        dict_length += 1;
    }
    dictionary = realloc(dictionary, (size_t) (dict_length + 1));
    dictionary[dict_length] = NULL; //null terminator of array of strings

    *dict = dictionary;
    return 0;
}


int main() {
    printf("Hello, World!\n");
    unsigned char plaintext[] = "This is a top secret.";
    char cipher_hex[] = "8d20e5056a8d24d0462ce74e4904c1b5"
                        "13e10d1df4a2ef2ad4540fae1ca0aaf9";
    char *test_cipher = NULL;
    char ** dict;
    char *key;
    int i = 0;
    char *iv;

    iv = (char *) calloc(17, sizeof(char));

    char *ref_cipher = hexstr_to_char(cipher_hex);

    if(read_dict(&dict) != 0) { //pointer to dictonary
        printf("error reading in dictonary\n");
        return 1;
    }
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(context, EVP_aes_128_cbc(), NULL, NULL, NULL);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(context) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(context) == 16);

    EVP_CipherInit_ex(context, NULL, NULL, key, iv, 1);

    while(strcmp(ref_cipher, test_cipher) != 0) {
        key = dict[i];
        EVP_CipherInit_ex(context, NULL, NULL, key, NULL, 1);

        EVP_CipherUpdate(context, test_cipher, strlen(plaintext), plaintext, strlen(plaintext));

    }
    printf("key: %s\n", dict[i]);


    BN_CTX_free(context);
    context = NULL;

    return 0;
}