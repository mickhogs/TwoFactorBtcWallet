package threshold.mr04;

import static threshold.mr04.Util.compressPoint;
import static threshold.mr04.Util.randomFromZn;
import static threshold.mr04.Util.randomFromZnStar;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;

import threshold.mr04.data.PublicParameters;
import threshold.mr04.data.Round1Message;
import threshold.mr04.data.Round2Message;
import threshold.mr04.data.Round3Message;
import threshold.mr04.data.Round4Message;

public class SignatureTest {
    // curve initialization from bitcoinj
    public static final ECDomainParameters CURVE;
    public static final BigInteger q;
    public static final ECPoint G;
    public BigInteger privateKey;
    public BigInteger aliceShare;
    public BigInteger bobShare;
    public SecureRandom rand = new SecureRandom();
    public PaillierPublicKey alicesPallierPubKey;
    public PaillierPublicKey otherPallierPubKey;

    public int kPrime = 2500;

    // from paiilier
    BigInteger N;
    BigInteger Nsquared;
    BigInteger g;

    //from other paillier
    BigInteger NPrime;
    BigInteger nPrimeSquared;
    BigInteger gPrime;

    //known by alice only--the random values used for the ciphertexts
    BigInteger r1;
    BigInteger r2;

    //known only by bob
    BigInteger rPrime1;
    BigInteger rPrime2;

    BigInteger uPrime;

    //for zkp1
    public BigInteger nHat;
    public BigInteger h1;
    public BigInteger h2;

    public byte[] publicKey;

    public Paillier paillier;

    static {
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        CURVE = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(),
                params.getH());
        q = params.getN();
        G = CURVE.getG();
    }

    public SignatureTest(int t) {
        /*
          paillier = new Paillier(256 * (3 * t + 3) + 1, 100);
          N = paillier.n;
         g = paillier.g;
         */
        System.out.println("Sig test");
        paillier = new Paillier(256 * (3 * t + 3) + 1, 100);
        do {
            privateKey = new BigInteger(256, rand);
        } while (privateKey.compareTo(q) != -1);
        do {
            aliceShare = new BigInteger(256, rand);
        } while (aliceShare.compareTo(q) != -1);

        bobShare = privateKey.multiply(aliceShare.modInverse(q)).mod(q);
        publicKey = compressPoint(G.multiply(privateKey), CURVE).getEncoded();

        N = paillier.n;
        Nsquared = paillier.nSquared;
        g = paillier.g;
        NPrime = N;
        nPrimeSquared = Nsquared;
        gPrime = g;
        alicesPallierPubKey = new PaillierPublicKey(N, g);
        otherPallierPubKey = new PaillierPublicKey(NPrime, gPrime);

        BigInteger p;
        BigInteger q;
        BigInteger pPrime;
        BigInteger qPrime;
        BigInteger pPrimeqPrime;

        // test values generated once
        p = new BigInteger(
                "17271679500853259237907722112751090572344800097015650067978430270487273362948741147217221813745737065180756833730757525261462768665613913991131866427719227116416050757312058537669863033032226737303616055612946759317498902390429962641420385908878962752920616873839178969530873172616563238953946312567371782591332025913655844884298189560341459584575856552380036842708310909041007");
        q = new BigInteger(
                "13679349955941400890712354406298795275148106390181318180078538082105703681760410189143971341297852299262662291675627451676813043044062128463388674582632527760707881341179231681719822452194383803410464575649942094118927642199654813323117910392205153242518651987825467217332192201895032548164952095659406396661838348254559489136525332853888735013679714339724169847186090393923859");
        nHat = p.multiply(q);
        pPrime = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
        qPrime = q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
        pPrimeqPrime = pPrime.multiply(qPrime);

        nHat = new BigInteger(
                "236265348219031028683877903779794583288133448965189876633172199463965937811734525033886348183516464403767263317068502789995146148476597858603529345098222167037074791697475407133100492052420936164017066989044809778683277508981350909365181664384969506055989949161038910237490286231913220898888898550119944346304287939272439092448425173582810085209210330872274174796291879141154264344024567264311257082458994017914690811934028317106440081424569441620446616120508191186105218521858324295862764641813408141323916415583638438889085203928556051826507935182374079848700614782735015373342034690531915817024516827597964967251650856472951391789020213816437502823052104436682903113920471066679858792706111846416415108340535853752521173567367174813214653861466686013");

        h2 = randomFromZnStar(nHat, rand);

        BigInteger x = randomFromZn(pPrimeqPrime, rand);
        h1 = h2.modPow(x, nHat);

    }

    public static PublicParameters generateParamsforBitcoin(int k, int kPrime, SecureRandom rand, PaillierPublicKey alicesPaillierPubKey) {

        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        ECDomainParameters CURVE = new ECDomainParameters(params.getCurve(), params.getG(),
                params.getN(), params.getH());
        Paillier otherPaillier = new Paillier(kPrime, k);
        PaillierPublicKey otherPaillierPubKey = new PaillierPublicKey(otherPaillier.n,
                otherPaillier.g);

        int primeCertainty = k;
        BigInteger p;
        BigInteger q;
        BigInteger pPrime;
        BigInteger qPrime;
        BigInteger pPrimeqPrime;
        BigInteger nHat;
        
        

        do {
            p = new BigInteger(kPrime / 2, primeCertainty, rand);
        } while (!p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2))
                .isProbablePrime(primeCertainty));

        pPrime = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));

        do {
            q = new BigInteger(kPrime / 2, primeCertainty, rand);
        } while (!q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2))
                .isProbablePrime(primeCertainty));

        qPrime = q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));

        // generate nhat. the product of two safe primes, each of length kPrime/2
        nHat = p.multiply(q);

        BigInteger h2 = randomFromZnStar(nHat, rand);
        pPrimeqPrime = pPrime.multiply(qPrime);

        BigInteger x = randomFromZn(pPrimeqPrime, rand);
        BigInteger h1 = h2.modPow(x, nHat);

        return new PublicParameters(CURVE, nHat, kPrime, h1, h2, alicesPaillierPubKey,
                otherPaillierPubKey);

    };

    public static void main(String[] args) {
            
        SignatureTest t = new SignatureTest1(2);
        System.out.println("got t");
        // set the private key to null - no more private key
        t.privateKey = null;
        PaillierPublicKey alicesPaillierPubKey = t.alicesPallierPubKey;
        PublicParameters params = generateParamsforBitcoin(100, 256 * (3 * 2 + 3) + 1, t.rand, alicesPaillierPubKey);
        System.out.println("got PublicParameters");
            Alice alice = new Alice(t.aliceShare, t.publicKey, t.rand, t.paillier, params);
            System.out.println("got alice");
            Bob bob = new Bob(t.bobShare, t.publicKey, t.rand, params);
            System.out.println("got bob");

            byte[] message = new byte[] { 1, 2, 4, 3 };

        
        Round1Message r1m = alice.aliceToBobRound1(message);
        Round2Message r2m = bob.bobToAliceRound2(r1m);
        Round3Message r3m = alice.aliceToBobRound3(r2m);
        Round4Message r4m = bob.bobToAliceRound4(r3m);
        BigInteger[] sig = alice.aliceOutput(r4m);
        System.out.println("Threshold signature");
        for(BigInteger signature : sig) {
            System.out.println(signature);
        }
       
        
        System.out.println(Util.verifySignature(message, sig[0], sig[1], t.publicKey, CURVE));
        BigInteger privKey = t.privateKey;
        // test
        ECDSASigner signer = new ECDSASigner();
//        signer.init(true, new ECPrivateKeyParameters(privKey, CURVE));
//        BigInteger[] signature = signer.generateSignature(message);
//        System.out.println(new ASN1Integer(signature[0]).getPositiveValue());
        
//        System.out.println("generated signature");
//        for(BigInteger s : signature) {
//          System.out.println(s);
//        }
    }
}