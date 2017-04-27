using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Linq;


namespace Akamai.Auth.Token
{

	public class AuthToken
	{
		/** Current time when using startTime */
		public static readonly long NOW = 0;

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
			TokenType = tokenType;
			TokenName = tokenName;
			Key = key;
			Algorithm = algorithm;
			Salt = salt;
			Ip = ip;
			Payload = payload;
			SessionId = sessionId;
			StartTime = startTime;
			EndTime = endTime;
			WindowSeconds = windowSeconds;
			FieldDelimiter = fieldDelimiter;
			EscapeEarly = escapeEarly;
			Verbose = verbose;
		}

		static int Main(string[] args)
		{
			AuthToken at = new AuthTokenBuilder()
							.Key(Secret.AT_ENCRYPTION_KEY)
							.WindowSeconds(500)
                            .EscapeEarly(false)
							.Build();

            Console.WriteLine(string.Format("http://auth-token.akamaized.net/q_ignore?{0}={1}", at.TokenName, at.GenerateURLToken("/q_ignore")));
			return 0;
		}

        private static byte[] _HexStringToByteArray(string hex)
		{
			return Enumerable.Range(0, hex.Length)
							 .Where(x => x % 2 == 0)
							 .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
							 .ToArray();
		}

		private String _EscapeEarly(String text)
		{
			if (EscapeEarly)
			{
				return Regex.Replace(Uri.EscapeUriString(text),
									 "(%..)",
									 m => m.Groups[1].Value.ToLower());
			}
			else
			{
				return text;
			}
		}

        private String _GenerateToken(String path, bool isUrl)
		{
			if (StartTime == NOW)
			{
				StartTime = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
			}
			else if (StartTime != null && WindowSeconds < 0)
			{
				throw new AuthTokenException("startTime must be ( > 0 )");
			}

			if (EndTime == null)
			{
				if (WindowSeconds != null && WindowSeconds > 0)
				{
					if (StartTime == null)
					{
						EndTime = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds +
							WindowSeconds;
					}
					else
					{
						EndTime = StartTime + WindowSeconds;
					}
				}
				else
				{
					throw new AuthTokenException("You must provide an expiration time or a duration window ( > 0 )");
				}
			}
			else if (EndTime <= 0)
			{
				throw new AuthTokenException("endTime must be ( > 0 )");
			}

			if (StartTime != null && (EndTime <= StartTime))
			{
				throw new AuthTokenException("Token will have already expired.");
			}

			if (Verbose)
			{
				Console.WriteLine("Akamai Token Generation Parameters");
				if (isUrl)
				{
					Console.WriteLine("    URL             : " + path);
				}
				else
				{
					Console.WriteLine("    ACL             : " + path);
				}
				Console.WriteLine("    Token Type      : " + TokenType);
				Console.WriteLine("    Token Name      : " + TokenName);
				Console.WriteLine("    Key/Secret      : " + Key);
				Console.WriteLine("    Algo            : " + Algorithm);
				Console.WriteLine("    Salt            : " + Salt);
				Console.WriteLine("    IP              : " + Ip);
				Console.WriteLine("    Payload         : " + Payload);
				Console.WriteLine("    Session ID      : " + SessionId);
				Console.WriteLine("    Start Time      : " + StartTime);
				Console.WriteLine("    Window(seconds) : " + WindowSeconds);
				Console.WriteLine("    End Time        : " + EndTime);
				Console.WriteLine("    Field Delimiter : " + FieldDelimiter);
				Console.WriteLine("    ACL Delimiter   : " + ACL_DELIMITER);
				Console.WriteLine("    Escape Early    : " + EscapeEarly);
			}


			StringBuilder newToken = new StringBuilder();
			if (!string.IsNullOrEmpty(Ip))
			{
				newToken.Append(string.Format("ip={0}{1}", Ip, FieldDelimiter));
			}

			if (StartTime != null)
			{
				newToken.Append(string.Format("st={0}{1}", StartTime, FieldDelimiter));
			}

			newToken.Append(string.Format("exp={0}{1}", EndTime, FieldDelimiter));

			if (!isUrl)
			{
				newToken.Append(string.Format("acl={0}{1}", path, FieldDelimiter));
			}

			if (!string.IsNullOrEmpty(SessionId))
			{
				newToken.Append(string.Format("id={0}{1}", SessionId, FieldDelimiter));
			}

			if (!string.IsNullOrEmpty(Payload))
			{
				newToken.Append(string.Format("data={0}{1}", Payload, FieldDelimiter));
			}

			StringBuilder hashSource = new StringBuilder(newToken.ToString());
			if (isUrl)
			{
				hashSource.Append(string.Format("url={0}{1}", path, FieldDelimiter));
			}

			if (!string.IsNullOrEmpty(Salt))
			{
				hashSource.Append(string.Format("salt={0}{1}", Salt, FieldDelimiter));
			}

            hashSource.Remove(hashSource.Length-1, 1);

			try
			{
				HMAC hmac = HMAC.Create(Algorithm);
                hmac.Key = _HexStringToByteArray(Key);

				byte[] rawHmac = hmac.ComputeHash(Encoding.ASCII.GetBytes(hashSource.ToString()));

				StringBuilder hmacStr = new StringBuilder();
				foreach (var b in rawHmac)
				{
					hmacStr.AppendFormat("{0:x2}", b);
				}

				return string.Format("{0}hmac={1}", newToken, hmacStr);
			}
			catch (Exception e)
			{
				throw new AuthTokenException(e.ToString());
			}
		}
		
		public String GenerateURLToken(String url)
		{
			if (string.IsNullOrEmpty(url))
			{
				throw new AuthTokenException("You must provide a URL.");
			}

			return _GenerateToken(url, true);
		}

		public String GenerateACLToken(String acl)
		{
			if (string.IsNullOrEmpty(acl))
			{
				throw new AuthTokenException("You must provide an ACL.");
			}

			return _GenerateToken(acl, false);
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
				tokenName = value;
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

		public String Algorithm
		{
			get { return algorithm; }
			set
			{
				if (value.ToLower().Equals("sha256"))
				{
					algorithm = "HMACSHA256";
				}
				else if (value.ToLower().Equals("sha1"))
				{
					algorithm = "HMACSHA1";
				}
				else if (value.ToLower().Equals("md5"))
				{
					algorithm = "HMACMD5";
				}
				else
				{
					throw new AuthTokenException("Unknown Algorithm");
				}
			}
		}

		public String Salt
		{

			get { return salt; }
			set { salt = value; }
		}

		public String Ip
		{
			get { return ip; }
			set { ip = value; }
		}

		public String Payload
		{
			get { return payload; }
			set { payload = value; }
		}

		public String SessionId
		{
			get { return sessionId; }
			set { sessionId = value; }
		}

		public long? StartTime
		{
			get { return startTime; }
			set { startTime = value; }
		}

		public long? EndTime
		{
			get { return endTime; }
			set { endTime = value; }
		}

		public long? WindowSeconds
		{
			get { return windowSeconds; }
			set { windowSeconds = value; }
		}

		public char FieldDelimiter
		{
			get { return fieldDelimiter; }
			set { fieldDelimiter = value; }
		}

		public bool EscapeEarly
		{
			get { return escapeEarly; }
			set { escapeEarly = value; }
		}

		public bool Verbose
		{
			get { return verbose; }
			set { verbose = value; }
		}
		public static byte[] ToByteArray(string me)
		{
			int len = me.Length;
			byte[] data = new byte[len / 2];
			for (int i = 0; i < len; i += 2)
			{
				int val1 = -1, val2 = -1;

				try
				{
					val1 = Convert.ToInt32(me[i].ToString(), 16) << 4;
				}
				catch (FormatException)
				{
				}
				catch (ArgumentException)
				{
				}

				try
				{
					val2 = Convert.ToInt32(me[i + 1].ToString(), 16);
				}
				catch (FormatException)
				{
				}
				catch (ArgumentException)
				{
				}

				val1 += val2;
				data[i / 2] = Convert.ToByte(val1);
			}
			return data;
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
		public AuthTokenException(String msg) : base(msg) { }
	}
}
