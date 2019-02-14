using Newtonsoft.Json.Linq;
using System;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using VstsDemoBuilder.Models;
using VstsRestAPI;
using VstsRestAPI.ProjectsAndTeams;

namespace VstsDemoBuilder.Controllers
{

    public class AccountController : Controller
    {
        private readonly AccessDetails accessDetails = new AccessDetails();
        private TemplateSelection.Templates templates = new TemplateSelection.Templates();

        [HttpGet]
        [AllowAnonymous]
        public ActionResult Unsupported_browser()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public ActionResult Verify(LoginModel model, string id)
        {
            Session.Clear();
            Session["EnableExtractor"] = "false";
            if (!string.IsNullOrEmpty(model.EnableExtractor))
            {
                Session["EnableExtractor"] = model.EnableExtractor;
            }
            var browser = Request.Browser.Type;
            if (browser.Contains("InternetExplorer"))
            {
                return RedirectToAction("Unsupported_browser", "Account");
            }

            try
            {
                if (!string.IsNullOrEmpty(model.name))
                {
                    if (System.IO.File.Exists(Server.MapPath("~") + @"\Templates\TemplateSetting.json"))
                    {
                        string privateTemplatesJson = System.IO.File.ReadAllText(Server.MapPath("~") + @"\Templates\TemplateSetting.json");
                        templates = Newtonsoft.Json.JsonConvert.DeserializeObject<TemplateSelection.Templates>(privateTemplatesJson);
                        if (templates != null)
                        {
                            bool flag = false;
                            foreach (var grpTemplate in templates.GroupwiseTemplates)
                            {
                                foreach (var template in grpTemplate.Template)
                                {
                                    if (template.Name != null && template.Name.ToLower() == model.name.ToLower())
                                    {
                                        flag = true;
                                        Session["templateName"] = model.name;
                                    }
                                }
                            }
                            if (flag == false)
                            {
                                Session["templateName"] = null;
                            }
                        }
                    }
                }
                if (!string.IsNullOrEmpty(model.Event))
                {
                    string eventsTemplate = Server.MapPath("~") + @"\Templates\Events.json";
                    if (System.IO.File.Exists(eventsTemplate))
                    {
                        string eventContent = System.IO.File.ReadAllText(eventsTemplate);
                        var jItems = JObject.Parse(eventContent);
                        if (jItems[model.Event] != null)
                        {
                            model.Event = jItems[model.Event].ToString();
                        }
                        else
                        {
                            model.Event = string.Empty;
                        }
                    }
                }
            }
            catch { }
            return View(model);
        }

        //[HttpGet]
        //[AllowAnonymous]
        //public ActionResult Verify(LoginModel model, string id)
        //{
        //    try
        //    {
        //        if (!string.IsNullOrEmpty(model.Event))
        //        {
        //            string eventsTemplate = Server.MapPath("~") + @"\Templates\Events.json";
        //            if (System.IO.File.Exists(eventsTemplate))
        //            {
        //                string eventContent = System.IO.File.ReadAllText(eventsTemplate);
        //                var jItems = JObject.Parse(eventContent);
        //                if (jItems[model.Event] != null)
        //                {
        //                    model.Event = jItems[model.Event].ToString();
        //                }
        //                else
        //                {
        //                    model.Event = string.Empty;
        //                }
        //            }
        //        }
        //    }
        //    catch { }

        //    return View(model);
        //}

        [HttpPost]
        [AllowAnonymous]
        public ActionResult Verify(LoginModel model)
        {
            try
            {

                string _credentials = Convert.ToBase64String(System.Text.ASCIIEncoding.ASCII.GetBytes(string.Format("{0}:{1}", "", model.PAT)));
                Configuration _inputConfiguration = new Configuration() { UriString = string.Format("http://{0}:{1}/{2}/", model.TFSserverName, model.Port, model.Collection), VersionNumber = "4.1", PersonalAccessToken = model.PAT };

                Projects objProject = new Projects(_inputConfiguration);
                bool isAccountValid = objProject.IsAccountHasProjects();
                if (isAccountValid)
                {
                    string TFSUriString = string.Format("http://{0}:{1}/{2}/", model.TFSserverName, model.Port, model.Collection);
                    Session["TFSUriString"] = TFSUriString;
                    Session["PAT"] = model.PAT;
                    Session["Collection"] = model.Collection;
                    FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(1, TFSUriString, DateTime.Now, DateTime.Now.AddMinutes(FormsAuthentication.Timeout.TotalMinutes), false, model.PAT, FormsAuthentication.FormsCookiePath);
                    string cookie = FormsAuthentication.Encrypt(ticket);
                    HttpCookie ck = new HttpCookie(FormsAuthentication.FormsCookieName, cookie);
                    ck.Path = FormsAuthentication.FormsCookiePath;
                    Response.Cookies.Add(ck);
                    Session["visited"] = 1;
                    return RedirectToAction("Create", "Environment", new { SelectedTemplate = model.Template, TFSserverName = model.TFSserverName, Port = model.Port, Collection = model.Collection });
                }

            }
            catch (Exception ex)
            {
                model.Message = "LoginFailed: " + ex.Message;
                return RedirectToAction("Verify", new { Message = model.Message, id = string.Empty });
            }

            model.Message = "Invalid PAT";
            return RedirectToAction("Verify", new { Message = model.Message });
        }


        /// <summary>
        /// Get Account at the end of project provision
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [AllowAnonymous]
        public string GetAccountName()
        {
            if (Session["AccountName"] != null)
            {
                string accountName = Session["AccountName"].ToString();
                return accountName;
            }
            else
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Index view which calls VSTS OAuth
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult Index()
        {
            Session["visited"] = "1";

            //testing
            string url = "https://app.vssps.visualstudio.com/oauth2/authorize?client_id={0}&response_type=Assertion&state=User1&scope={1}&redirect_uri={2}";

            string redirectUrl = System.Configuration.ConfigurationManager.AppSettings["RedirectUri"];
            string clientId = System.Configuration.ConfigurationManager.AppSettings["ClientId"];
            string AppScope = System.Configuration.ConfigurationManager.AppSettings["appScope"];
            url = string.Format(url, clientId, AppScope, redirectUrl);
            return Redirect(url);
        }

        /// <summary>
        /// Sign out
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult SignOut()
        {
            Session.Clear();
            return Redirect("https://app.vssps.visualstudio.com/_signout");
        }
    }
}
