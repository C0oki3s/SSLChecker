#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <pthread.h>
#include <json-c/json.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

json_object *json_array;
pthread_mutex_t json_mutex = PTHREAD_MUTEX_INITIALIZER;

void initialize_json_array()
{
    json_array = json_object_new_array();
}

void append_to_json_array(json_object *jobj)
{
    pthread_mutex_lock(&json_mutex);
    json_object_array_add(json_array, jobj);
    pthread_mutex_unlock(&json_mutex);
}

typedef struct
{
    char *ip;
    int port;
    const char *cafile;
    char *fqdn;
    int is_ipv6;
} ThreadArgs;

// Error handling
void handle_openssl_error()
{
    ERR_print_errors_fp(stderr);
    abort();
}

// Initialize OpenSSL
void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Cleanup OpenSSL
void cleanup_openssl()
{
    EVP_cleanup();
}

// Create SSL context
SSL_CTX *create_context()
{
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        handle_openssl_error();
    }
    return ctx;
}

// Resolve IP to FQDN for SNI
char *resolve_fqdn(const char *ip)
{
    struct addrinfo hints, *res;
    char hostname[NI_MAXHOST];
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(ip, NULL, &hints, &res) != 0)
    {
        return NULL;
    }

    if (getnameinfo(res->ai_addr, res->ai_addrlen, hostname, NI_MAXHOST, NULL, 0, 0) != 0)
    {
        freeaddrinfo(res);
        return NULL;
    }

    freeaddrinfo(res);
    return strdup(hostname);
}

// Connect and get certificate
X509 *get_certificate(const char *hostname, int port, const char *cafile, const char *sni, int timeout_sec, int *connection_blocked)
{
    *connection_blocked = 0;
    SSL_CTX *ctx = create_context();

    if (SSL_CTX_load_verify_locations(ctx, cafile, NULL) != 1)
    {
        fprintf(stderr, "Error loading CA file.\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    BIO *bio = BIO_new_ssl_connect(ctx);
    SSL *ssl;
    BIO_get_ssl(bio, &ssl);
    if (!ssl)
    {
        fprintf(stderr, "Error creating SSL object.\n");
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (sni)
    {
        SSL_set_tlsext_host_name(ssl, sni);
    }

    char conn_str[256];
    snprintf(conn_str, sizeof(conn_str), "%s:%d", hostname, port);
    BIO_set_conn_hostname(bio, conn_str);
    BIO_set_nbio(bio, 1);

    struct timeval start_time, current_time;
    gettimeofday(&start_time, NULL);
    while (1)
    {
        int ret = BIO_do_connect(bio);
        if (ret > 0)
        {
            break;
        }

        if (BIO_should_retry(bio))
        {
            gettimeofday(&current_time, NULL);
            if ((current_time.tv_sec - start_time.tv_sec) >= timeout_sec)
            {
                fprintf(stderr, "Error connecting to %s:%d (timeout).\n", hostname, port);
                *connection_blocked = 1;
                BIO_free_all(bio);
                SSL_CTX_free(ctx);
                return NULL;
            }
            usleep(100000);
        }
        else
        {
            fprintf(stderr, "Connection failed to %s:%d.\n", hostname, port);
            *connection_blocked = 1;
            BIO_free_all(bio);
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert)
    {
        fprintf(stderr, "No certificate retrieved from %s:%d.\n", hostname, port);
        *connection_blocked = 1;
    }

    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return cert;
}

// Check security issues
void check_security_issues(X509 *cert, json_object *jobj)
{
    json_object *issues = json_object_new_object();

    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey)
    {
        int key_bits = EVP_PKEY_bits(pkey);
        if (key_bits < 2048)
        {
            json_object_object_add(issues, "ShortKey", json_object_new_string("Key length below 2048 bits"));
        }
        EVP_PKEY_free(pkey);
    }

    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);
    int days, seconds;
    if (ASN1_TIME_diff(&days, &seconds, not_before, not_after))
    {
        double validity_days = days + (seconds / (24.0 * 3600.0));
        if (validity_days > 825)
        {
            json_object_object_add(issues, "LongValidity", json_object_new_string("Validity period exceeds 825 days"));
        }
    }

    json_object_object_add(issues, "ROCA", json_object_new_string("Potential ROCA vulnerability (requires external testing)"));
    json_object_object_add(issues, "Heartbleed", json_object_new_string("Not applicable"));

    json_object_object_add(jobj, "SecurityIssues", issues);
}

// Check revocation
void check_revocation(X509 *cert, json_object *jobj)
{
    json_object *revocation = json_object_new_object();
    json_object_object_add(revocation, "Status", json_object_new_string("OCSP check not implemented"));
    json_object_object_add(jobj, "Revocation", revocation);
}

// Write JSON to file
void write_json_array_to_file(const char *filename)
{
    pthread_mutex_lock(&json_mutex);
    FILE *fp = fopen(filename, "w");
    if (fp)
    {
        fprintf(fp, "%s\n", json_object_to_json_string_ext(json_array, JSON_C_TO_STRING_PRETTY));
        fclose(fp);
    }
    else
    {
        fprintf(stderr, "Failed to open file for writing: %s\n", filename);
    }
    pthread_mutex_unlock(&json_mutex);
}

// Certificate details
void print_certificate_details(X509 *cert, json_object *jobj)
{
    X509_NAME *issuer_name = X509_get_issuer_name(cert);
    if (issuer_name)
    {
        char issuer[256];
        X509_NAME_oneline(issuer_name, issuer, sizeof(issuer));
        json_object_object_add(jobj, "Issuer", json_object_new_string(issuer));
    }

    X509_NAME *subject_name = X509_get_subject_name(cert);
    if (subject_name)
    {
        char cn[256];
        X509_NAME_get_text_by_NID(subject_name, NID_commonName, cn, sizeof(cn));
        json_object *jcn_array = json_object_new_array();
        json_object_array_add(jcn_array, json_object_new_string(cn));
        json_object_object_add(jobj, "CN", jcn_array);
    }

    STACK_OF(GENERAL_NAME) *san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_names)
    {
        int san_count = sk_GENERAL_NAME_num(san_names);
        json_object *jsan_array = json_object_new_array();
        for (int i = 0; i < san_count; i++)
        {
            const GENERAL_NAME *name = sk_GENERAL_NAME_value(san_names, i);
            if (name->type == GEN_DNS)
            {
                char *dns_name = (char *)ASN1_STRING_get0_data(name->d.dNSName);
                json_object_array_add(jsan_array, json_object_new_string(dns_name));
            }
        }
        json_object_object_add(jobj, "SANs", jsan_array);
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    }
}

// Certificate chain
void print_certificate_chain(X509 *cert, json_object *jobj)
{
    json_object *jchain_array = json_object_new_array();
    int depth = 0;
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!store || !ctx)
    {
        fprintf(stderr, "Error creating X509 store context.\n");
        return;
    }
    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1)
    {
        fprintf(stderr, "Error initializing X509 store context.\n");
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        return;
    }
    while (cert)
    {
        json_object *jcert = json_object_new_object();
        char subject[256], issuer[256];
        X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
        X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
        json_object_object_add(jcert, "Depth", json_object_new_int(depth));
        json_object_object_add(jcert, "Subject", json_object_new_string(subject));
        json_object_object_add(jcert, "Issuer", json_object_new_string(issuer));
        json_object_array_add(jchain_array, jcert);
        X509 *issuer_cert = NULL;
        if (X509_STORE_CTX_get1_issuer(&issuer_cert, ctx, cert) != 1)
        {
            break;
        }
        X509_free(cert);
        cert = issuer_cert;
        depth++;
    }
    json_object_object_add(jobj, "CertificateChain", jchain_array);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
}

// Forward declaration
void process_ip_port(const char *ip, int port, void *data);

// Thread function
void *thread_function(void *arg)
{
    ThreadArgs *args = (ThreadArgs *)arg;
    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "IP", json_object_new_string(args->ip));
    json_object_object_add(jobj, "Port", json_object_new_int(args->port));
    if (args->fqdn)
    {
        json_object_object_add(jobj, "FQDN", json_object_new_string(args->fqdn));
    }

    int connection_blocked = 0;
    X509 *cert = get_certificate(args->ip, args->port, args->cafile, args->fqdn, 5, &connection_blocked);
    if (cert)
    {
        print_certificate_details(cert, jobj);
        print_certificate_chain(cert, jobj);
        check_security_issues(cert, jobj);
        check_revocation(cert, jobj);
        X509_free(cert);
    }
    else
    {
        json_object_object_add(jobj, "Error", json_object_new_string(connection_blocked ? "Connection blocked (possible IDP)" : "No certificate retrieved"));
    }

    append_to_json_array(jobj);
    free(args->ip);
    if (args->fqdn)
        free(args->fqdn);
    free(args);
    return NULL;
}

// Parse CIDR notation
void parse_cidr(const char *cidr, void (*callback)(const char *, int, void *), void *data)
{
    char ip[INET6_ADDRSTRLEN];
    int prefix;
    if (sscanf(cidr, "%[^/]/%d", ip, &prefix) != 2)
    {
        fprintf(stderr, "Invalid CIDR format: %s\n", cidr);
        return;
    }

    int is_ipv6 = strchr(ip, ':') != NULL;
    if (is_ipv6)
    {
        struct in6_addr addr;
        inet_pton(AF_INET6, ip, &addr);
        uint64_t count = 1ULL << (128 - prefix);
        count = count > 1000 ? 1000 : count; // Limit for practicality
        for (uint64_t i = 0; i < count; i++)
        {
            char current_ip[INET6_ADDRSTRLEN];
            struct in6_addr current = addr;
            // Simplified increment (not comprehensive)
            inet_ntop(AF_INET6, &current, current_ip, INET6_ADDRSTRLEN);
            callback(current_ip, 443, data);
        }
    }
    else
    {
        struct in_addr addr;
        inet_pton(AF_INET, ip, &addr);
        uint32_t mask = ~((1 << (32 - prefix)) - 1);
        uint32_t start = ntohl(addr.s_addr) & mask;
        uint32_t count = 1 << (32 - prefix);
        for (uint32_t i = 0; i < count; i++)
        {
            struct in_addr current;
            current.s_addr = htonl(start + i);
            char current_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &current, current_ip, INET_ADDRSTRLEN);
            callback(current_ip, 443, data);
        }
    }
}

// Parse IP range
void parse_ip_range(const char *range, void (*callback)(const char *, int, void *), void *data)
{
    char start_ip[INET6_ADDRSTRLEN], end_ip[INET6_ADDRSTRLEN];
    sscanf(range, "%[^-]-%s", start_ip, end_ip);

    int is_ipv6 = strchr(start_ip, ':') != NULL;
    if (is_ipv6)
    {
        char current_ip[INET6_ADDRSTRLEN];
        strcpy(current_ip, start_ip); // Simplified
        callback(current_ip, 443, data);
    }
    else
    {
        struct in_addr start, end;
        inet_pton(AF_INET, start_ip, &start);
        inet_pton(AF_INET, end_ip, &end);
        for (unsigned int i = ntohl(start.s_addr); i <= ntohl(end.s_addr); i++)
        {
            struct in_addr current;
            current.s_addr = htonl(i);
            char current_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &current, current_ip, INET_ADDRSTRLEN);
            callback(current_ip, 443, data);
        }
    }
}

// Parse port range
void parse_port_range(const char *range, void (*callback)(const char *, int, void *), void *data, const char *ip)
{
    int start_port, end_port;
    if (sscanf(range, "%d-%d", &start_port, &end_port) == 2)
    {
        for (int port = start_port; port <= end_port; port++)
        {
            callback(ip, port, data);
        }
    }
    else
    {
        int port = atoi(range);
        callback(ip, port ? port : 443, data);
    }
}

// Process IPs from file
void process_ip_file(const char *filename, const char *port_range, const char *cafile, pthread_t *threads, int *thread_count)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        fprintf(stderr, "Failed to open input file: %s\n", filename);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), file))
    {
        line[strcspn(line, "\n")] = 0;
        char *ip = strtok(line, ":");
        char *port_str = strtok(NULL, ":");

        if (ip)
        {
            const char *ports = port_str ? port_str : port_range;
            parse_port_range(ports, process_ip_port, &(struct { const char *cafile; pthread_t *threads; int *thread_count; }){.cafile = cafile, .threads = threads, .thread_count = thread_count}, ip);
        }
    }
    fclose(file);
}

// Callback for IP and port
void process_ip_port(const char *ip, int port, void *data)
{
    struct
    {
        const char *cafile;
        pthread_t *threads;
        int *thread_count;
    } *ctx = data;
    ThreadArgs *args = malloc(sizeof(ThreadArgs));
    args->ip = strdup(ip);
    args->port = port;
    args->cafile = ctx->cafile;
    args->fqdn = resolve_fqdn(ip);
    args->is_ipv6 = strchr(ip, ':') != NULL;
    pthread_create(&ctx->threads[*ctx->thread_count], NULL, thread_function, args);
    (*ctx->thread_count)++;
}

int main(int argc, char **argv)
{
    if (argc < 4 || argc > 5)
    {
        fprintf(stderr, "Usage: %s [--file <ip_file> | --cidr <cidr> | --range <ip_range>] <port_range> <cafile>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *input = NULL, *port_range = NULL, *cafile = NULL;
    int is_file = 0, is_cidr = 0, is_range = 0;

    if (strcmp(argv[1], "--file") == 0)
    {
        is_file = 1;
        input = argv[2];
        port_range = argv[3];
        cafile = argv[4];
    }
    else if (strcmp(argv[1], "--cidr") == 0)
    {
        is_cidr = 1;
        input = argv[2];
        port_range = argv[3];
        cafile = argv[4];
    }
    else if (strcmp(argv[1], "--range") == 0)
    {
        is_range = 1;
        input = argv[2];
        port_range = argv[3];
        cafile = argv[4];
    }
    else
    {
        fprintf(stderr, "Invalid option. Use --file, --cidr, or --range.\n");
        return EXIT_FAILURE;
    }

    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    init_openssl();
    initialize_json_array();

    pthread_t threads[1000];
    int thread_count = 0;

    if (is_file)
    {
        process_ip_file(input, port_range, cafile, threads, &thread_count);
    }
    else if (is_cidr)
    {
        parse_cidr(input, process_ip_port, &(struct { const char *cafile; pthread_t *threads; int *thread_count; }){.cafile = cafile, .threads = threads, .thread_count = &thread_count});
    }
    else if (is_range)
    {
        parse_ip_range(input, process_ip_port, &(struct { const char *cafile; pthread_t *threads; int *thread_count; }){.cafile = cafile, .threads = threads, .thread_count = &thread_count});
    }

    for (int i = 0; i < thread_count; i++)
    {
        pthread_join(threads[i], NULL);
    }

    gettimeofday(&end_time, NULL);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1e6;
    json_object *stats = json_object_new_object();
    json_object_object_add(stats, "ScanTimeSeconds", json_object_new_double(elapsed));
    append_to_json_array(stats);

    write_json_array_to_file("output.json");
    cleanup_openssl();
    return EXIT_SUCCESS;
}