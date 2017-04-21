using System;


namespace Akamai.Auth.Token
{

    public class AuthToken
    {
        /** Current time when using startTime */
        public static readonly long? NOW = 0;

        /** ! delimiter when using ACL */
        public static String ACL_DELIMITER = "!";

        /** select a preset. (Not Supported Yet) */
        private String tokenType;

        /** parameter name for the new token. */
        private String tokenName;

        /** secret required to generate the token. It must be hexadecimal digit string with even-length. */
        private String key;

        /** to use to generate the token. (sha1, sha256, or md5) */
        private String algorithm;

        /** additional data validated by the token but NOT included in the token body. It will be deprecated. */
        private String salt;

        /** IP Address to restrict this token to. Troublesome in many cases (roaming, NAT, etc) so not often used. */
        private String ip;

        /** additional text added to the calculated digest. */
        private String payload;

        /** the session identifier for single use tokens or other advanced cases. */
        private String sessionId;

        /** what is the start time? ({@code NOW} for the current time) */
        private long? startTime;

        /** when does this token expire? It overrides {@code windowSeconds} */
        private long? endTime;

        /** How long is this token valid for? */
        private long? windowSeconds;

        /** character used to delimit token body fields. */
        private char fieldDelimiter;

        /** causes strings to be url encoded before being used. */
        private bool escapeEarly;

        /** print all parameters. */
        private bool verbose;

        public AuthToken(
            String tokenType,
            String tokenName,
            String key,
            String algorithm,
            String salt,
            String ip,
            String payload,
            String sessionId,
            long? startTime,
            long? endTime,
            long? windowSeconds,
            char fieldDelimiter,
            bool escapeEarly,
            bool verbose)
        {
            this.tokenType = tokenType;
            this.tokenName = tokenName;
            this.key = key;
            this.algorithm = algorithm;
            this.salt = salt;
            this.ip = ip;
            this.payload = payload;
            this.sessionId = sessionId;
            this.startTime = startTime;
            this.endTime = endTime;
            this.windowSeconds = windowSeconds;
            this.fieldDelimiter = fieldDelimiter;
            this.escapeEarly = escapeEarly;
            this.verbose = verbose;
        }

        public String TokenType
        {
            get { return tokenType; }
            set { tokenType = value; }
        }

        public String TokenName
        {
            get { return tokenName; }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    throw new AuthTokenException("You must provide a token name.");
                }
                tokenType = value;
            }
        }

        public String Key
        {
            get { return key; }
            set
            {
				if (string.IsNullOrEmpty(value))
				{
					throw new AuthTokenException("You must provide a secret in order to generate a new token.");
				}
				key = value;
            }
        }


        /**
         * @param algorithm algorithm
         */
        public void SetAlgorithm(String algorithm)
        {
            if (!algorithm.equalsIgnoreCase("md5") &&
            !algorithm.equalsIgnoreCase("sha1") &&
            !algorithm.equalsIgnoreCase("sha256"))
            {
                throw new AuthTokenException("Unknown Algorithm");
            }
            if (algorithm.equalsIgnoreCase("sha256"))
                this.algorithm = "HmacSHA256";
            else if (algorithm.equalsIgnoreCase("sha1"))
                this.algorithm = "HmacSHA1";
            else if (algorithm.equalsIgnoreCase("md5"))
                this.algorithm = "HmacMD5";
        }

        /**
         * @param salt salt
         */
        public void SetSalt(String salt)
        {
            this.salt = salt;
        }

        /**
         * @param ip ip
         */
        public void SetIp(String ip)
        {
            this.ip = ip;
        }

        /**
         * @param payload payload
         */
        public void SetPayload(String payload)
        {
            this.payload = payload;
        }

        /**
         * @param sessionId sessionId
         */
        public void SetSessionId(String sessionId)
        {
            this.sessionId = sessionId;
        }

        /**
         * @param startTime startTime
         */
        public void SetStartTime(Long startTime)
        {
            this.startTime = startTime;
        }

        /**
         * @param endTime endTime
         */
        public void SetEndTime(Long endTime)
        {
            this.endTime = endTime;
        }

        /**
         * @param windowSeconds windowSeconds
         */
        public void SetWindowSeconds(Long windowSeconds)
        {
            this.windowSeconds = windowSeconds;
        }

        /**
         * @param fieldDelimiter fieldDelimiter
         */
        public void SetFieldDelimiter(char fieldDelimiter)
        {
            this.fieldDelimiter = fieldDelimiter;
        }

        /**
         * @param escapeEarly escapeEarly
         */
        public void SetEscapeEarly(bool escapeEarly)
        {
            this.escapeEarly = escapeEarly;
        }
        /**
         * @param verbose verbose
         */
        public void SetVerbose(bool verbose)
        {
            this.verbose = verbose;
        }


        /**
         * @return tokenName
         */
        public String getTokenName()
        {
            return this.tokenName;
        }

        /**
         * @return key
         */
        public String getKey()
        {
            return this.key;
        }

        /**
         * @return algorithm
         */
        public String getAlgorithm()
        {
            return this.algorithm;
        }

        /**
         * @return salt
         */
        public String getSalt()
        {
            return this.salt;
        }

        /**
         * @return ip
         */
        public String getIp()
        {
            return this.ip;
        }

        /**
         * @return payload
         */
        public String getPayload()
        {
            return this.payload;
        }

        /**
         * @return sessionId
         */
        public String getSessionId()
        {
            return this.sessionId;
        }

        /**
         * @return startTime
         */
        public long getStartTime()
        {
            return this.startTime;
        }

        /**
         * @return endTime
         */
        public long getEndTime()
        {
            return this.endTime;
        }

        /**
         * @return windowSeconds
         */
        public long getwindowSeconds()
        {
            return this.windowSeconds;
        }

        /**
         * @return fieldDelimiter
         */
        public char getFieldDelimiter()
        {
            return this.fieldDelimiter;
        }

        /**
         * @return escapeEarly
         */
        public bool isEscapeEarly()
        {
            return this.escapeEarly;
        }

        /**
         * @return verbose
         */
        public bool isVerbose()
        {
            return this.verbose;
        }
    }

    public class AuthTokenBuilder
    {
        /** select a preset. (Not Supported Yet) */
        private String tokenType = null;

        /** parameter name for the new token. */
        private String tokenName = "__token__";

        /** secret required to generate the token. It must be hexadecimal digit string with even-length. */
        private String key = null;

        /** to use to generate the token. (sha1, sha256, or md5) */
        private String algorithm = "sha256";

        /** additional data validated by the token but NOT included in the token body. It will be deprecated. */
        private String salt = null;

        /** IP Address to restrict this token to. Troublesome in many cases (roaming, NAT, etc) so not often used. */
        private String ip = null;

        /** additional text added to the calculated digest. */
        private String payload = null;

        /** the session identifier for single use tokens or other advanced cases. */
        private String sessionId = null;

        /** what is the start time? */
        private long? startTime = null;

        /** when does this token expire? It overrides {@code windowSeconds} */
        private long? endTime = null;

        /** How long is this token valid for? */
        private long? windowSeconds = null;

        /** character used to delimit token body fields. */
        private char fieldDelimiter = '~';

        /** causes strings to be url encoded before being used. */
        private bool escapeEarly = false;

        /** print all parameters. */
        private bool verbose = false;

        /**
	     * @param tokenType tokenType
	     * @return AuthTokenBuilder
	     */
        public AuthTokenBuilder TokenType(String tokenType)
        {
            this.tokenType = tokenType;
            return this;
        }

        /**
         * @param tokenName tokenName
         * @return AuthTokenBuilder
         */
        public AuthTokenBuilder TokenName(String tokenName)
        {
            this.tokenName = tokenName;
            return this;
        }

        /**
         * @param key key
         * @return AuthTokenBuilder
         */
        public AuthTokenBuilder Key(String key)
        {
            this.key = key;
            return this;
        }

        /**
         * @param algorithm algorithm
         * @return AuthTokenBuilder
         */
        public AuthTokenBuilder Algorithm(String algorithm)
        {
            this.algorithm = algorithm;
            return this;
        }

        /**
         * @param salt salt
         * @return AuthTokenBuilder
         */
        public AuthTokenBuilder Salt(String salt)
        {
            this.salt = salt;
            return this;
        }

        /**
         * @param ip ip
         * @return AuthTokenBuilder
         */
        public AuthTokenBuilder Ip(String ip)
        {
            this.ip = ip;
            return this;
        }

        /**
         * @param payload payload
         * @return AuthTokenBuilder
         */
        public AuthTokenBuilder Payload(String payload)
        {
            this.payload = payload;
            return this;
        }

        /**
         * @param sessionId sessionId
         * @return AuthTokenBuilder
         */
        public AuthTokenBuilder SessionId(String sessionId)
        {
            this.sessionId = sessionId;
            return this;
        }

        /**
         * @param startTime startTime
         * @return AuthTokenBuilder
         */
        public AuthTokenBuilder StartTime(long startTime)
        {
            this.startTime = startTime;
            return this;
        }

        /**
         * @param endTime endTime
         * @return AuthTokenBuilder
         */
        public AuthTokenBuilder EndTime(long endTime)
        {
            this.endTime = endTime;
            return this;
        }

        /**
         * @param windowSeconds windowSeconds
         * @return AuthTokenBuilder
         */
        public AuthTokenBuilder WindowSeconds(long windowSeconds)
        {
            this.windowSeconds = windowSeconds;
            return this;
        }

        /**
         * @param fieldDelimiter fieldDelimiter
         * @return AuthTokenBuilder
         */
        public AuthTokenBuilder FieldDelimiter(char fieldDelimiter)
        {
            this.fieldDelimiter = fieldDelimiter;
            return this;
        }

        /**
         * @param escapeEarly escapeEarly
         * @return AuthTokenBuilder
         */
        public AuthTokenBuilder EscapeEarly(bool escapeEarly)
        {
            this.escapeEarly = escapeEarly;
            return this;
        }

        /**
         * @param verbose verbose
         * @return AuthTokenBuilder
         */
        public AuthTokenBuilder Verbose(bool verbose)
        {
            this.verbose = verbose;
            return this;
        }

        /**
         * build an {@link AuthToken} instance
         * 
         * @return {@link AuthToken}
         */
        public AuthToken Build()
        {
            return new AuthToken(
                tokenType, tokenName,
                key, algorithm, salt,
                ip, payload, sessionId,
                startTime, endTime, windowSeconds,
                fieldDelimiter, escapeEarly, verbose

            );
        }
    }

    public class AuthTokenException : Exception
    {
        /**
	     * @param msg exception message
	     */
        public AuthTokenException(String msg)
        {

        }
    }
}
