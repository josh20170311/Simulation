namespace Simulation {
    public partial class Form1 : Form {
        Authenticator authenticator = new Authenticator();
        IdentityProvider identityProvider = new IdentityProvider();
        RelyingParty relyingParty = new RelyingParty();
        public Form1() {
            InitializeComponent();

            /**
             * 將authnticator跟Bob綁在一起
             */
            identityProvider.initialize(authenticator, "Bob");

            relyingParty.register(authenticator, new User("Bob NickName"), identityProvider);
        }
    }
}