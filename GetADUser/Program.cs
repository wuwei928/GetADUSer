using System;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace GetADUser
{
    class Program
    {
        static void Main(string[] args)
        {
            //DirectoryConnection();
            LdapConnection();
            //AccountManagementGetUsers();
            Console.Read();
        }

        private static void AccountManagementGetUsers()
        {
            var principalContext = new PrincipalContext(ContextType.Domain, "192.168.1.199", "CN=Users,DC=weihu,DC=com", ContextOptions.ServerBind, "administrator", "Password2");
            var principals = new GroupPrincipal(principalContext);
            foreach (var members in principals.Members)
            {
                Console.WriteLine(members.DisplayName);
            }
        }

        private static void DirectoryConnection()
        {
            var directoryEntry = new DirectoryEntry("LDAP://192.168.1.199", "administrator", "Password2");
            var filter = "(&(objectClass=user)(objectCategory=person)(mail=*)(company=Forefront Consulting Group))";
            var propertiesToLoad = new[] { "sAMAccountName", "givenName", "sn", "mail", "userPrincipalName" };
            var directorySearcher = new DirectorySearcher(directoryEntry, filter, propertiesToLoad);

            var users = directorySearcher.FindAll().Cast<SearchResult>();
            foreach (var user in users)
            {
                if (user.Properties.Contains("samaccountname"))
                {
                    Console.WriteLine(user.Properties["samaccountname"][0]);
                }
            }
        }

        private static void LdapConnection()
        {
            var server = "Ffazure01.cloudapp.net";
            var userName = "visitapp@ffcg.se";
            var passsword = "Besok";
            var port = 63600;
            var filter = "Ou=Users,ou=ffcg.local,dc=ffcg,dc=local";
            var propertiesToLoad = new string[] { "sAMAccountName" };
            try
            {
                //AD connection
                var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(server, port));
                ldapConnection.SessionOptions.SecureSocketLayer = true;
                ldapConnection.SessionOptions.ProtocolVersion = 3;
                ldapConnection.SessionOptions.VerifyServerCertificate = ServerCallback;
                ldapConnection.Credential = new NetworkCredential(userName, passsword);
                ldapConnection.AuthType = AuthType.Negotiate;
                ldapConnection.Bind();
                Console.WriteLine("connection success");
                //GetUser
                const string ldapSearchFilter = "(objectClass=*)";
                var searchRequest = new SearchRequest(filter, ldapSearchFilter, SearchScope.Subtree, propertiesToLoad);
                var searchResponse = (SearchResponse)ldapConnection.SendRequest(searchRequest);

                if (searchResponse == null) return;
                foreach (SearchResultEntry entry in searchResponse.Entries)
                {
                    var name = GetStringAttributeValue(entry, "sAMAccountName");
                    Console.WriteLine(name);
                }
            }
            catch (Exception e)
            {
                throw new Exception("Connect AD server error");
            }
        }

        private static bool ServerCallback(LdapConnection connection, X509Certificate certificate)
        {
            return true;
        }

        private static string GetStringAttributeValue(SearchResultEntry entry, string attribute)
        {
            try
            {
                var attrs = entry.Attributes;
                if (!attrs.Contains(attribute)) return null;

                var directoryAttribute = attrs[attribute];
                var attr = directoryAttribute.GetValues(typeof(string)).First() as string ?? "";
                return attr;
            }
            catch (Exception e)
            {
                throw new Exception("Could not get attribute " + attribute + "for " + entry.DistinguishedName, e);
            }
        }
    }
}
