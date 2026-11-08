// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Validates one signed document with the EU DSS library, offline, and
 * prints what DSS concluded, one fact per line.
 *
 * <p>Usage: {@code DssGate --anchor <der>... [--detached <original>] <signed>}
 *
 * <p>The trust anchors are the only trusted certificates: no trusted list
 * is loaded and no online source is configured, so DSS sees exactly the
 * material the document carries. Validation uses DSS's default policy
 * ({@code policy/constraint.xml} of {@code dss-policy-jaxb}) at the
 * current time.
 *
 * <p>Output, for each signature in document order:
 *
 * <pre>
 * signature &lt;id&gt; format=&lt;SignatureLevel&gt; indication=&lt;Indication&gt; subindication=&lt;SubIndication or -&gt;
 * error &lt;id&gt; &lt;message&gt;
 * warning &lt;id&gt; &lt;message&gt;
 * </pre>
 *
 * then {@code container=<ASiCContainerType or ->} and {@code signatures=<count>}.
 */
public final class DssGate {
  private DssGate() {}

  public static void main(String[] args) {
    List<String> anchors = new ArrayList<>();
    List<String> detached = new ArrayList<>();
    String signed = null;
    for (int at = 0; at < args.length; at++) {
      switch (args[at]) {
        case "--anchor" -> anchors.add(args[++at]);
        case "--detached" -> detached.add(args[++at]);
        default -> {
          if (signed != null) {
            usage();
          }
          signed = args[at];
        }
      }
    }
    if (signed == null || anchors.isEmpty()) {
      usage();
    }

    CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
    for (String anchor : anchors) {
      CertificateToken token = DSSUtils.loadCertificate(new File(anchor));
      trusted.addCertificate(token);
    }
    CommonCertificateVerifier verifier = new CommonCertificateVerifier();
    verifier.setTrustedCertSources(trusted);
    verifier.setAIASource(null);
    verifier.setOcspSource(null);
    verifier.setCrlSource(null);

    SignedDocumentValidator validator =
        SignedDocumentValidator.fromDocument(new FileDocument(signed));
    validator.setCertificateVerifier(verifier);
    List<DSSDocument> originals = new ArrayList<>();
    for (String original : detached) {
      originals.add(new FileDocument(original));
    }
    if (!originals.isEmpty()) {
      validator.setDetachedContents(originals);
    }

    Reports reports = validator.validateDocument();
    SimpleReport simple = reports.getSimpleReport();
    List<String> ids = simple.getSignatureIdList();
    for (String id : ids) {
      Object sub = simple.getSubIndication(id);
      System.out.println(
          "signature " + id
              + " format=" + simple.getSignatureFormat(id)
              + " indication=" + simple.getIndication(id)
              + " subindication=" + (sub == null ? "-" : sub));
      simple.getAdESValidationErrors(id)
          .forEach(message -> System.out.println("error " + id + " " + message.getValue()));
      simple.getAdESValidationWarnings(id)
          .forEach(message -> System.out.println("warning " + id + " " + message.getValue()));
    }
    Object container = simple.getContainerType();
    System.out.println("container=" + (container == null ? "-" : container));
    System.out.println("signatures=" + ids.size());
  }

  private static void usage() {
    System.err.println("usage: DssGate --anchor <der>... [--detached <original>] <signed>");
    System.exit(2);
  }
}
