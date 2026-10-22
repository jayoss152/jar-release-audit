package io.github.jarreleaseaudit;

import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;
import javax.xml.XMLConstants;
import javax.xml.parsers.SAXParserFactory;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayDeque;

/** Streaming XML inspection with DTD/entity access disabled before parsing. */
final class XmlCredentials extends DefaultHandler {
    private record Frame(boolean credential, StringBuilder text) { }
    private final ArrayDeque<Frame> stack = new ArrayDeque<>();
    private int nodes;
    private boolean found;
    static boolean inspect(String text) throws IOException {
        if (text.length() > 1_048_576) throw new IOException("XML text limit");
        try {
            var factory = SAXParserFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setXIncludeAware(false);
            var reader = factory.newSAXParser().getXMLReader();
            reader.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            reader.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            var handler = new XmlCredentials();
            reader.setContentHandler(handler);
            reader.setErrorHandler(handler);
            reader.setEntityResolver((publicId, systemId) -> { throw new SAXException("External entity forbidden"); });
            reader.parse(new InputSource(new StringReader(text)));
            return handler.found;
        } catch (Exception e) { throw new IOException("Malformed, unsupported or over-budget XML"); }
    }
    @Override public void startElement(String uri, String local, String name, Attributes attributes) throws SAXException {
        if (stack.size() >= 32 || ++nodes > 10000) throw new SAXException("XML structure budget");
        String key = attributes.getValue("key");
        if (key == null) key = attributes.getValue("name");
        boolean credential = CredentialValues.key(name) || (key != null && CredentialValues.key(key))
                || (!stack.isEmpty() && stack.peek().credential());
        String value = attributes.getValue("value");
        if (credential && value != null && JarScanner.literalValue("\"" + value + "\"")) found = true;
        stack.push(new Frame(credential, new StringBuilder()));
    }
    @Override public void characters(char[] chars, int start, int length) {
        if (!stack.isEmpty()) stack.peek().text().append(chars, start, length);
    }
    @Override public void endElement(String uri, String local, String name) {
        Frame frame = stack.pop();
        if (frame.credential() && JarScanner.literalValue("\"" + frame.text().toString().strip() + "\"")) found = true;
    }
    @Override public void error(SAXParseException e) throws SAXException { throw e; }
    @Override public void fatalError(SAXParseException e) throws SAXException { throw e; }
}
