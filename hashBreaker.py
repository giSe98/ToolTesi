import sys, getopt
import md5Ex, sha1Ex, sha256Ex, sha512Ex

encode_formats = ["raw", "hex"]
decode_formats = ["raw", "hex"]
hash_type_list= ["md5", "sha1", "sha256", "sha512"]

data = ''
data_format = 'raw'
signature = ''
signature_format = 'hex'
append = ''
append_format = 'raw'
format_hash = ''
len_secret = 6
out_data_format = ''
out_signature_format = ''

def usage():
    print(
        "\n"
        "HASH BREAKER\n"
        "--------------------------------------------------------------------------------------------------------------------\n"
        "\n"
        "Usage (in random order): \n"
        "  hashBreaker.py --data=<data> --signature=<signature> --format=<format> --append=<data> --secret=<length>[options] \n"
        "\n"
        "INPUT OPTIONS\n"
        "-d --data=<data>                   The original string that we're going to extend\n"
        "--data-format=<format>             The format the string is being passed in as. Default: raw.\n"
        "                                   Valid formats: {}\n"
        "-s --signature=<signature>         The original signature\n"
        "--signature-format=<format>        The format the signature is being passed in as. Default: hex.\n"
        "                                   Valid formats: {}\n"
        "-f --format=<format>               The hash-type of the signature.\n"
        "                                   Valid types: {}\n"
        "-a --append=<data>                 The data to append to the string.\n"
        "--append-format=<format>           The format the string is being passed in as.Default: raw.\n"
        "                                   Valid formats: {}\n"
        "-l --secret=<length>               The length of the secret, if known. Default: 5.\n"
        "\n"
        "OUTPUT OPTIONS\n"
        "--out-data-format=<format>         Output data format.\n"
        "                                   Valid formats: {}\n"
        "--out-signature-format=<format>    Output signature format.\n"
        "                                   Valid formats: {}\n"
        "\n"
        "OTHER OPTIONS\n"
        "-h --help                          Display the usage (this).\n"
        "--test                             Run the test suite.\n"
        "\n"
        "--------------------------------------------------------------------------------------------------------------------\n"
        "Version with MD5, SHA1, SHA256, SHA512\n"
        .format(', '.join(decode_formats), ', '.join(decode_formats), ', '.join(hash_type_list), ', '.join(decode_formats), ', '.join(encode_formats), ', '.join(encode_formats[1:]))
    )
    
    sys.exit()

def error(message):
    print(message)
    usage()

def test():
    msg = "user_id=5&send=110.00&to=7"
    signature = "89ce79966a901d94a184a93fef956b29"
    secret = 6
    hash_type = "md5"
    append = "&send=1000.00&to=789456"
    h = md5Ex.md5Ex(msg, signature, secret, append)
    newData = h.extend()
    newSignature = h.hexdigest()

    print("BODY POST: \n"
          "     Original Data: {}\n"
          "     Original Signature: {}\n"
          "SECRET LENGTH: {}\n"
          "TYPE: {}\n"
          "APPEND: {}\n"
          "     Desired New Data: {}\n"
          "New Data: {}\n"
          "New Signature: {}\n"
          .format(msg, signature, secret, hash_type, append, msg+append, newData, newSignature))
    sys.exit()

def main(argv):
    global data, data_format, signature, signature_format, append, append_format, format_hash, len_secret, out_data_format, out_signature_format
    
    if len(argv) == 0:
        usage()
    short_options = "h:d:s:a:f:l:"
    long_options = ["help", "data=", "data-format=", "signature=", "signature-format =", "append=", 
                    "append-format=", "format=", "secret=", "out-data-format=", "out-signature-format=", "test"] 

    try:
        opts, args = getopt.getopt(argv, short_options, long_options)
    except getopt.GetoptError:
        usage()

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
        elif opt in ("-d", "--data"):
            data = arg
        elif opt == "--data-format":
            if not(arg in decode_formats):
                error("Unknown option passed to --data-format")
            if arg == "hex":
                try:
                    data_format = arg.decode('hex')
                except:
                    error("Wrong format passed to --data_format")
        elif opt in ("-s", "--signature"):
            if arg == '':
                error("The signature field cannot be empty")
            signature = arg
        elif opt == "--signature-format":
            if not(arg in decode_formats()):
                error("Unknown option passed to --signature-format")
            if arg == "raw":
                try:
                    signature_format = arg.encode('hex')
                except:
                    error("Wrong format passed to --signature-format")
        elif opt in ("-a", "--append"):
            if arg == '':
                error("The append field cannot be empty")
            append = arg
        elif opt == "--append-format":
            if not(arg in decode_formats):
                error("Unknown option passed to --append-format")
            if arg == "raw":
                try:
                    append_format = arg.encode('hex')
                except:
                    error("Wrong format passed to --append-format")
        elif opt in ("-f", "--format"):
            if not(arg in hash_type_list):
                error("Invalid hash type passed to --format")
            format_hash = arg
        elif opt in ("-l", "--secret"):
            if arg < 0:
                error("Wrong length passed to --secret")
            len_secret = int(arg)
        elif opt == "--out-data-format":
            if not(arg in encode_formats):
                error("Unknown option passed to --out-data-format")
            out_data_format = arg
        elif opt == "--out-signature-format":
            if not(arg in encode_formats):
                error("Unknown option passed to --out-signature-format")
            out_signature_format = arg
        elif opt == "--test":
            test()   

    if data == '' or signature == '' or append == '' or format_hash == '':
        error("Something went wrong, check the input !")

    if format_hash == "md5":
        if len(signature) != 32:
            error("Incompatible signature")
        h = md5Ex.md5Ex(data, signature, len_secret, append)
    if format_hash == "sha1":
        if len(signature) != 40:
            error("Incompatible signature")
        h = sha1Ex.sha1Ex(data, signature, len_secret,append)
    if format_hash == "sha256":
        if len(signature) != 64:
            error("Incompatible signature")
        h = sha256Ex.sha256Ex(data, signature, len_secret,append)
    if format_hash == "sha512":
        if len(signature) != 128:
            error("Incompatible signature")
        h = sha512Ex.sha512Ex(data, signature, len_secret,append)

    newData = h.extend()
        
    if out_data_format == "hex":
        newData = h.getHex()
        
    newSignature = h.hexdigest()

    print("Type: {}\n"
          "Secret len: {}\n"
          "New Data: {}\n"
          "New Signature: {}\n"
          .format(format_hash.upper(), len_secret, newData, newSignature))

if __name__ == "__main__":
    main(sys.argv[1:])
