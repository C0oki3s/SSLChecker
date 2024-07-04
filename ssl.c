#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509v3.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <json-c/json.h>

json_object *json_array;

void initialize_json_array() {
    json_array = json_object_new_array();
}

void append_to_json_array(json_object *jobj) {
    json_object_array_add(json_array, jobj);
}


// Define a struct to hold IP and port information
typedef struct {
    char *ip;
    int port;
    const char *cafile;
} ThreadArgs;

// Error handling function
void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Initialize OpenSSL
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Cleanup OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}

// Create an SSL context
SSL_CTX* create_context() {
    const SSL_METHOD *method = SSLv23_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        handle_openssl_error();
    }

    return ctx;
}

// Connect to the server and get the certificate with timeout
X509* get_certificate(const char *hostname, int port, const char *cafile, int timeout_sec) {
    SSL_CTX *ctx = create_context();

    // Set CA file
    if (SSL_CTX_load_verify_locations(ctx, cafile, NULL) != 1) {
        fprintf(stderr, "Error loading CA file.\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Set up the connection
    BIO *bio = BIO_new_ssl_connect(ctx);
    SSL *ssl;
    BIO_get_ssl(bio, &ssl);
    if (!ssl) {
        fprintf(stderr, "Error creating SSL object.\n");
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Construct the connection string
    char conn_str[256];
    snprintf(conn_str, sizeof(conn_str), "%s:%d", hostname, port);
    BIO_set_conn_hostname(bio, conn_str);

    // Set non-blocking I/O
    BIO_set_nbio(bio, 1);

    // Connect to the server with timeout
    struct timeval start_time, current_time;
    gettimeofday(&start_time, NULL);
    while (1) {
        if (BIO_do_connect(bio) > 0) {
            break; // Connection established
        }

        gettimeofday(&current_time, NULL);
        if ((current_time.tv_sec - start_time.tv_sec) >= timeout_sec) {
            fprintf(stderr, "Error connecting to server (timeout).\n");
            BIO_free_all(bio);
            SSL_CTX_free(ctx);
            return NULL;
        }

        // Sleep for a short duration before retrying
        struct timespec sleep_time = {0, 100000}; // Sleep for 0.1 seconds
        nanosleep(&sleep_time, NULL);
    }

    // Get the certificate
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        fprintf(stderr, "Error retrieving server certificate.\n");
    }

    // Drop the connection
    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    return cert;
}


void write_json_array_to_file(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (fp) {
        fprintf(fp, "%s\n", json_object_to_json_string_ext(json_array, JSON_C_TO_STRING_PRETTY));
        fclose(fp);
    } else {
        fprintf(stderr, "Failed to open file for writing: %s\n", filename);
    }
}

void print_certificate_details(X509 *cert, json_object *jobj) {
    // Issuer
    X509_NAME *issuer_name = X509_get_issuer_name(cert);
    if (issuer_name) {
        char issuer[256];
        X509_NAME_oneline(issuer_name, issuer, sizeof(issuer));
        json_object_object_add(jobj, "Issuer", json_object_new_string(issuer));
    } else {
        fprintf(stderr, "No issuer information found in the certificate.\n");
    }

    // Common Name (CN)
    X509_NAME *subject_name = X509_get_subject_name(cert);
    if (subject_name) {
        char cn[256];
        X509_NAME_get_text_by_NID(subject_name, NID_commonName, cn, sizeof(cn));
        json_object *jcn_array = json_object_new_array();
        json_object_array_add(jcn_array, json_object_new_string(cn));
        json_object_object_add(jobj, "CN", jcn_array);
    } else {
        fprintf(stderr, "No Common Name (CN) found in the certificate.\n");
    }

    // Subject Alternative Names (SANs)
    STACK_OF(GENERAL_NAME) *san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_names) {
        int san_count = sk_GENERAL_NAME_num(san_names);
        json_object *jsan_array = json_object_new_array();
        if (san_count > 0) {
            for (int i = 0; i < san_count; i++) {
                const GENERAL_NAME *name = sk_GENERAL_NAME_value(san_names, i);
                if (name->type == GEN_DNS) {
                    char *dns_name = (char *)ASN1_STRING_get0_data(name->d.dNSName);
                    json_object_array_add(jsan_array, json_object_new_string(dns_name));
                }
            }
            json_object_object_add(jobj, "SANs", jsan_array);
        } else {
            json_object_object_add(jobj, "SANs", jsan_array); // Add empty array if no SANs
        }
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    } else {
        fprintf(stderr, "No Subject Alternative Names (SANs) found in the certificate.\n");
    }
}

void print_certificate_chain(X509 *cert, json_object *jobj) {
    json_object *jchain_array = json_object_new_array();
    int depth = 0;
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!store || !ctx) {
        fprintf(stderr, "Error creating X509 store context.\n");
        return;
    }
    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
        fprintf(stderr, "Error initializing X509 store context.\n");
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        return;
    }
    while (cert) {
        json_object *jcert = json_object_new_object();
        char subject[256], issuer[256];
        X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
        X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
        json_object_object_add(jcert, "Depth", json_object_new_int(depth));
        json_object_object_add(jcert, "Subject", json_object_new_string(subject));
        json_object_object_add(jcert, "Issuer", json_object_new_string(issuer));
        json_object_array_add(jchain_array, jcert);
        X509_STORE_CTX_cleanup(ctx);
        X509 *issuer_cert = NULL;
        if (X509_STORE_CTX_get1_issuer(&issuer_cert, ctx, cert) != 1) {
            break; // No more issuers
        }
        X509_free(cert);
        cert = issuer_cert;
        depth++;
    }
    json_object_object_add(jobj, "CertificateChain", jchain_array);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
}

// Function to be executed by each thread

void *thread_function(void *arg) {
    ThreadArgs *args = (ThreadArgs *)arg;
    X509 *cert = get_certificate(args->ip, args->port, args->cafile, 5); // Timeout set to 5 seconds
    if (!cert) {
        fprintf(stderr, "Failed to retrieve certificate for IP: %s Port: %d\n", args->ip, args->port);
        return NULL;
    }
    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "IP", json_object_new_string(args->ip));
    json_object_object_add(jobj, "Port", json_object_new_int(args->port));
    print_certificate_details(cert, jobj);
    print_certificate_chain(cert, jobj);

    // Append JSON object to the global JSON array
    append_to_json_array(jobj);

    X509_free(cert);
    return NULL;
}


int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_file> <cafile>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *input_file = argv[1];
    const char *cafile = argv[2];

    // Initialize OpenSSL
    init_openssl();

    // Open the input file
    FILE *file = fopen(input_file, "r");
    if (!file) {
        fprintf(stderr, "Failed to open input file.\n");
        cleanup_openssl();
        return EXIT_FAILURE;
    }

    // Initialize the JSON array
    initialize_json_array();

    char line[256];
    pthread_t threads[10]; // Assuming a maximum of 10 threads
    int thread_count = 0;

    while (fgets(line, sizeof(line), file) && thread_count < 10) {
        // Remove newline character
        line[strcspn(line, "\n")] = 0;

        // Split IP address and port
        char *ip = strtok(line, ":");
        char *port_str = strtok(NULL, ":");

        int port = port_str ? atoi(port_str) : 443;

        if (ip) {
            // Create thread arguments
            ThreadArgs *args = malloc(sizeof(ThreadArgs));
            args->ip = strdup(ip);
            args->port = port;
            args->cafile = cafile;

            // Create thread
            pthread_create(&threads[thread_count], NULL, thread_function, args);
            thread_count++;
        } else {
            fprintf(stderr, "Invalid input format: %s\n", line);
        }
    }

    // Wait for threads to finish
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    // Close the input file
    fclose(file);

    // Write the JSON array to a file
    write_json_array_to_file("output.json");

    // Cleanup OpenSSL
    cleanup_openssl();

    return EXIT_SUCCESS;
}