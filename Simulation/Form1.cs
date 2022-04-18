namespace Simulation {
    public partial class Form1 : Form {
        Authenticator authenticator = new Authenticator();
        IdentityProvider identityProvider = new IdentityProvider();
        RelyingParty relyingParty = new RelyingParty();
        public Form1() {
            InitializeComponent();

            /**
             * �Nauthnticator��Bob�j�b�@�_
             */
            identityProvider.initialize(authenticator, "Bob");

            relyingParty.register(authenticator, new User("Bob NickName"), identityProvider);
        }
    }
}