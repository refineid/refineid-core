// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! A small XML reader for signature files, and canonicalisation of one
//! element subtree under Canonical XML 1.0, Canonical XML 1.1 or
//! Exclusive XML Canonicalization 1.0.
//!
//! The reader accepts the XML an `XAdES` signature file is made of:
//! elements with namespaces, attributes, character data, `CDATA`
//! sections, the five predefined entity references and character
//! references, comments and processing instructions. Every element
//! records the byte range it occupies in the source. A document type
//! declaration, any other entity reference, an encoding other than
//! UTF-8 and every namespace misuse are refused: `ETSI EN 319 132-1`
//! signatures carry none of them, and a reader that resolves less than
//! the producer wrote would digest different bytes. Two elements
//! carrying the same `Id` are refused too, so a same-document
//! reference names one element or none (W3C XML Signature 1.1
//! sec.4.4.3.3).
//!
//! The canonicaliser renders one element and its descendants, the
//! element being the apex of the node set and its ancestors omitted, as
//! each of the three algorithms does, with or without comments: the
//! inclusive ones with every namespace in scope and the inherited
//! `xml:` attributes on the apex, the exclusive one with the prefixes
//! each element visibly utilises and those of an `InclusiveNamespaces
//! PrefixList`.
//!
//! # Conformance
//!
//! - W3C XML 1.0 (Fifth Edition) <https://www.w3.org/TR/xml/>: sec.2.2
//!   characters, sec.2.11 end-of-line handling, sec.3.3.3 attribute
//!   value normalisation (every attribute is `CDATA` without a DTD),
//!   sec.4.1 character and entity references, sec.4.6 the predefined
//!   entities.
//! - W3C Namespaces in XML 1.0 (Third Edition)
//!   <https://www.w3.org/TR/xml-names/>: sec.3 declaring namespaces,
//!   sec.6 applying them to elements and attributes.
//! - W3C Canonical XML 1.0
//!   <https://www.w3.org/TR/2001/REC-xml-c14n-20010315> sec.2.2 and
//!   sec.2.3: UTF-8, end tags for empty elements, attribute order, the
//!   escaping of attribute values and text, comments and processing
//!   instructions, a namespace node rendered unless the output parent
//!   carries it with the same value, `xmlns=""` only under an output
//!   parent with a default namespace, the `xml` namespace node never;
//!   sec.2.4: the apex of a subset renders the `xml:` attributes of
//!   its ancestors it does not carry itself.
//! - W3C Canonical XML 1.1 <https://www.w3.org/TR/xml-c14n11/>
//!   sec.2.4: only `xml:lang` and `xml:space` are inherited, `xml:id`
//!   is not, and `xml:base` is fixed up with the `join-URI-References`
//!   function over RFC 3986 sec.5.2.
//! - W3C Exclusive XML Canonicalization 1.0
//!   <https://www.w3.org/TR/xml-exc-c14n/> sec.3: a namespace
//!   declaration is rendered on the outermost element of the subset
//!   that visibly utilises its prefix, and `xml:` attributes are not
//!   inherited from ancestors; sec.4: a prefix the `PrefixList` names
//!   is rendered wherever it is in scope and differs from what the
//!   nearest output ancestor rendered, `#default` naming the default
//!   namespace.

use core::ops::Range;

/// The namespace the `xml` prefix is bound to by definition
/// (Namespaces in XML 1.0 sec.3).
pub const NAMESPACE_XML: &str = "http://www.w3.org/XML/1998/namespace";

/// The namespace the `xmlns` prefix is bound to by definition
/// (Namespaces in XML 1.0 sec.3).
const NAMESPACE_XMLNS: &str = "http://www.w3.org/2000/xmlns/";

/// The prefix bound to [`NAMESPACE_XML`].
const PREFIX_XML: &str = "xml";

/// The attribute name, or prefix, of a namespace declaration.
const PREFIX_XMLNS: &str = "xmlns";

/// Deepest element nesting accepted. A signature file nests about ten
/// levels deep; the bound keeps the recursive canonicaliser's stack
/// small whatever the input.
const MAX_DEPTH: usize = 128;

/// Most nodes (elements, text runs, comments and processing
/// instructions) a document may hold. A signature file over a
/// container of thousands of files holds tens of thousands; the bound
/// keeps a hostile file from growing the tree without limit.
const MAX_NODES: usize = 1 << 18;

/// The byte order mark a UTF-8 document may start with (XML 1.0
/// sec.4.3.3).
const BYTE_ORDER_MARK: char = '\u{FEFF}';

/// Opens an XML declaration (XML 1.0 sec.2.8).
const XML_DECLARATION_OPEN: &str = "<?xml";

/// Opens a document type declaration (XML 1.0 sec.2.8).
const DOCTYPE_OPEN: &str = "<!DOCTYPE";

/// Opens a comment (XML 1.0 sec.2.5).
const COMMENT_OPEN: &str = "<!--";

/// Closes a comment.
const COMMENT_CLOSE: &str = "-->";

/// Opens a `CDATA` section (XML 1.0 sec.2.7).
const CDATA_OPEN: &str = "<![CDATA[";

/// Closes a `CDATA` section.
const CDATA_CLOSE: &str = "]]>";

/// Opens a processing instruction (XML 1.0 sec.2.6).
const PI_OPEN: &str = "<?";

/// Closes a processing instruction or the XML declaration.
const PI_CLOSE: &str = "?>";

/// Opens an end tag (XML 1.0 sec.3.1).
const END_TAG_OPEN: &str = "</";

/// Closes an empty-element tag (XML 1.0 sec.3.1).
const EMPTY_TAG_CLOSE: &str = "/>";

/// Prefix of a hexadecimal character reference (XML 1.0 sec.4.1).
const CHAR_REF_HEX: &str = "#x";

/// Prefix of a decimal character reference.
const CHAR_REF_DECIMAL: &str = "#";

/// Radix of a hexadecimal character reference.
const RADIX_HEX: u32 = 16;

/// Radix of a decimal character reference.
const RADIX_DECIMAL: u32 = 10;

/// Lower bound of the first `Char` range above the control characters
/// (XML 1.0 sec.2.2 production 2).
const CHAR_RANGE_1_START: char = '\u{20}';

/// Upper bound of the first `Char` range, below the surrogates.
const CHAR_RANGE_1_END: char = '\u{D7FF}';

/// Lower bound of the second `Char` range, above the surrogates.
const CHAR_RANGE_2_START: char = '\u{E000}';

/// Upper bound of the second `Char` range; U+FFFE and U+FFFF are not
/// characters.
const CHAR_RANGE_2_END: char = '\u{FFFD}';

/// Lower bound of the supplementary-plane `Char` range.
const CHAR_RANGE_3_START: char = '\u{10000}';

/// The encoding name the XML declaration may carry (XML 1.0 sec.4.3.3).
const ENCODING_UTF8: &str = "UTF-8";

/// The identifier attribute a same-document reference names (W3C XML
/// Signature 1.1 sec.4.4.3.3, `ETSI EN 319 132-1` sec.4.2).
pub(crate) const ATTRIBUTE_ID: &str = "Id";

/// Why a document did not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlError {
    /// The bytes are not UTF-8.
    NotUtf8,
    /// The text is not well-formed XML, or misuses namespaces.
    Malformed(&'static str),
    /// Well-formed XML using a feature this reader refuses.
    Unsupported(&'static str),
    /// Elements nest deeper than this reader accepts.
    TooDeep,
    /// The document holds more nodes than this reader accepts.
    TooManyNodes,
}

impl core::fmt::Display for XmlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotUtf8 => f.write_str("the XML is not UTF-8"),
            Self::Malformed(what) => write!(f, "malformed XML: {what}"),
            Self::Unsupported(what) => write!(f, "unsupported XML: {what}"),
            Self::TooDeep => f.write_str("XML elements nest too deeply"),
            Self::TooManyNodes => f.write_str("XML document holds too many nodes"),
        }
    }
}

impl core::error::Error for XmlError {}

/// Whether canonicalisation keeps comments: the `#WithComments`
/// variant of each algorithm retains them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comments {
    /// Comment nodes are not rendered.
    Omitted,
    /// Comment nodes are rendered.
    Retained,
}

/// The canonicalisation algorithms this reader computes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Algorithm {
    /// Canonical XML 1.0: every namespace in scope rendered at the
    /// apex, every `xml:` attribute inherited from omitted ancestors.
    Canonical10,
    /// Canonical XML 1.1: as 1.0, with only `xml:lang` and `xml:space`
    /// inherited and `xml:base` fixed up.
    Canonical11,
    /// Exclusive XML Canonicalization 1.0, the prefixes of its
    /// `InclusiveNamespaces PrefixList` rendered as inclusive Canonical
    /// XML renders them.
    Exclusive(InclusivePrefixes),
}

/// One canonicalisation method: the algorithm and its comment mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canonicalization {
    /// The algorithm.
    pub algorithm: Algorithm,
    /// Whether comments are kept.
    pub comments: Comments,
}

impl Canonicalization {
    /// Exclusive XML Canonicalization 1.0 without a prefix list.
    #[must_use]
    pub fn exclusive(comments: Comments) -> Self {
        Self {
            algorithm: Algorithm::Exclusive(InclusivePrefixes::default()),
            comments,
        }
    }
}

/// The local name of `xml:base` (W3C XML Base sec.3).
const XML_BASE: &str = "base";

/// The simple inheritable attributes of Canonical XML 1.1 sec.2.4,
/// `xml:lang` and `xml:space`, by local name.
const SIMPLE_INHERITABLE: [&str; 2] = ["lang", "space"];

/// The `xml:` attributes the apex of a subset renders from its omitted
/// ancestors.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct InheritedXml {
    /// Attributes taken from the nearest ancestor that carries them.
    added: Vec<Attribute>,
    /// The fixed-up `xml:base` (Canonical XML 1.1 sec.2.4), replacing
    /// the element's own; empty means none is rendered.
    base: Option<String>,
}

/// One parsed attribute, namespace declarations excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Attribute {
    /// The prefix as written.
    prefix: Option<String>,
    /// The local part of the name.
    local: String,
    /// The namespace the prefix resolves to; `None` for an unprefixed
    /// attribute, which is in no namespace.
    namespace: Option<String>,
    /// The normalised value, references resolved.
    value: String,
}

impl Attribute {
    /// Whether this is the `xml:` attribute named `local`.
    fn is_xml(&self, local: &str) -> bool {
        self.namespace.as_deref() == Some(NAMESPACE_XML) && self.local == local
    }
}

/// One namespace declaration made on an element.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Declaration {
    /// The declared prefix; `None` for the default namespace.
    prefix: Option<String>,
    /// The namespace name; empty only when undeclaring the default.
    uri: String,
}

/// One child of an element.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    /// A child element, by index into the document's elements.
    Element(usize),
    /// Character data, references resolved and line ends normalised.
    Text(String),
    /// A comment's text.
    Comment(String),
    /// A processing instruction's target and data.
    ProcessingInstruction {
        /// The target name.
        target: String,
        /// The data after the separating whitespace; may be empty.
        data: String,
    },
}

/// One parsed element.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ElementData {
    /// The prefix as written.
    prefix: Option<String>,
    /// The local part of the name.
    local: String,
    /// The namespace the element is in, if any.
    namespace: Option<String>,
    /// The attributes, in source order.
    attributes: Vec<Attribute>,
    /// The namespace declarations made on this element.
    declarations: Vec<Declaration>,
    /// The children, in document order.
    children: Vec<Node>,
    /// The enclosing element.
    parent: Option<usize>,
    /// The bytes of the source the element occupies, start tag through
    /// end tag.
    span: Range<usize>,
}

/// Every element of a document, in document order, the root stored
/// apart so a document always has one.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Elements {
    /// The document element, index zero.
    root: ElementData,
    /// The elements after it, from index one.
    rest: Vec<ElementData>,
}

impl Elements {
    /// Split the parsed elements into the root and the rest.
    fn new(parsed: Vec<ElementData>) -> Result<Self, XmlError> {
        let mut parsed = parsed.into_iter();
        let root = parsed
            .next()
            .ok_or(XmlError::Malformed("no document element"))?;
        Ok(Self {
            root,
            rest: parsed.collect(),
        })
    }

    /// The element at `index`.
    fn get(&self, index: usize) -> Option<&ElementData> {
        match index.checked_sub(1) {
            None => Some(&self.root),
            Some(after_root) => self.rest.get(after_root),
        }
    }

    /// How many elements there are.
    fn len(&self) -> usize {
        self.rest.len().saturating_add(1)
    }
}

/// A parsed XML document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlDocument {
    /// The source text.
    source: String,
    /// Every element, in document order.
    elements: Elements,
}

impl XmlDocument {
    /// Parse a complete document.
    ///
    /// # Errors
    /// [`XmlError`] when the bytes are not UTF-8, not well-formed, use
    /// a refused feature, or nest deeper than this reader accepts.
    pub fn parse(source: Vec<u8>) -> Result<Self, XmlError> {
        let source = String::from_utf8(source).map_err(|_ignored| XmlError::NotUtf8)?;
        let elements = Elements::new(Parser::new(&source).document()?)?;
        Ok(Self { source, elements })
    }

    /// The document element.
    #[must_use]
    pub const fn root(&self) -> ElementRef<'_> {
        ElementRef {
            document: self,
            index: 0,
            data: &self.elements.root,
        }
    }

    /// Every element, in document order.
    pub fn elements(&self) -> impl Iterator<Item = ElementRef<'_>> {
        (0..self.elements.len()).filter_map(|index| self.element(index))
    }

    /// The source text the document was parsed from.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The element at `index`.
    fn element(&self, index: usize) -> Option<ElementRef<'_>> {
        self.elements.get(index).map(|data| ElementRef {
            document: self,
            index,
            data,
        })
    }
}

/// One element of a parsed document.
#[derive(Debug, Clone, Copy)]
pub struct ElementRef<'a> {
    /// The document the element belongs to.
    document: &'a XmlDocument,
    /// Its index in the document's elements.
    index: usize,
    /// Its parsed data.
    data: &'a ElementData,
}

impl PartialEq for ElementRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.document, other.document) && self.index == other.index
    }
}

impl Eq for ElementRef<'_> {}

impl<'a> ElementRef<'a> {
    /// The element's parsed data.
    const fn data(&self) -> &'a ElementData {
        self.data
    }

    /// The namespace the element is in, if any.
    #[must_use]
    pub fn namespace(&self) -> Option<&'a str> {
        self.data().namespace.as_deref()
    }

    /// The local part of the element's name.
    #[must_use]
    pub fn local_name(&self) -> &'a str {
        &self.data().local
    }

    /// Whether the element has this namespace and local name.
    #[must_use]
    pub fn is(&self, namespace: &str, local: &str) -> bool {
        self.namespace() == Some(namespace) && self.local_name() == local
    }

    /// The value of the attribute with this local name and no
    /// namespace.
    #[must_use]
    pub fn attribute(&self, local: &str) -> Option<&'a str> {
        self.data()
            .attributes
            .iter()
            .find(|attribute| attribute.namespace.is_none() && attribute.local == local)
            .map(|attribute| attribute.value.as_str())
    }

    /// The enclosing element.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        self.document.element(self.data().parent?)
    }

    /// The child elements, in document order.
    pub fn children(self) -> impl Iterator<Item = ElementRef<'a>> + 'a {
        let document = self.document;
        self.data()
            .children
            .iter()
            .filter_map(move |node| match node {
                Node::Element(index) => document.element(*index),
                Node::Text(_) | Node::Comment(_) | Node::ProcessingInstruction { .. } => None,
            })
    }

    /// The child elements with this namespace and local name.
    pub fn children_named(
        self,
        namespace: &'a str,
        local: &'a str,
    ) -> impl Iterator<Item = ElementRef<'a>> + 'a {
        self.children()
            .filter(move |child| child.is(namespace, local))
    }

    /// The first child element with this namespace and local name.
    #[must_use]
    pub fn child(&self, namespace: &'a str, local: &'a str) -> Option<Self> {
        self.children_named(namespace, local).next()
    }

    /// The element and every element inside it, in document order.
    pub fn descendants(self) -> impl Iterator<Item = ElementRef<'a>> + 'a {
        let document = self.document;
        let root = self;
        let end = self.data().span.end;
        let start = self.index;
        // Elements are stored in document order, so a subtree is the
        // contiguous run of elements that start inside its span.
        (start..document.elements.len())
            .filter_map(move |index| document.element(index))
            .take_while(move |element| element == &root || element.data().span.start < end)
    }

    /// The concatenated character data of the element's direct
    /// children.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = String::new();
        for node in &self.data().children {
            if let Node::Text(text) = node {
                out.push_str(text);
            }
        }
        out
    }

    /// The bytes of the source the element occupies, from the `<` of
    /// its start tag through the `>` of its end tag.
    #[must_use]
    pub fn span(&self) -> Range<usize> {
        self.data().span.clone()
    }

    /// The namespace `prefix` resolves to at this element: its own
    /// declarations, then its ancestors'. `None` for the default
    /// namespace means no default is in scope.
    fn resolve(&self, prefix: Option<&str>) -> Option<&'a str> {
        if prefix == Some(PREFIX_XML) {
            return Some(NAMESPACE_XML);
        }
        let mut current = Some(*self);
        while let Some(element) = current {
            if let Some(declaration) = element
                .data()
                .declarations
                .iter()
                .find(|declaration| declaration.prefix.as_deref() == prefix)
            {
                return (!declaration.uri.is_empty()).then_some(declaration.uri.as_str());
            }
            current = element.parent();
        }
        None
    }

    /// The element and its descendants under `method`, as the node set
    /// of this subtree: the form a same-document reference yields, and
    /// the form `ds:SignedInfo` is canonicalised in (W3C XML Signature
    /// 1.1 sec.4.4.3.3 and sec.4.4.1). The element is the apex of the
    /// subset; its ancestors are omitted, and the context they give is
    /// rendered as `method` says.
    #[must_use]
    pub fn canonicalize(&self, method: &Canonicalization) -> Vec<u8> {
        let mut out = String::new();
        let mut rendered = Vec::new();
        let inherited = self.inherited_xml_attributes(&method.algorithm);
        self.render(&mut out, &mut rendered, method, &inherited);
        out.into_bytes()
    }

    /// The namespace declarations in scope at this element, the
    /// innermost for each prefix, the default prefix as `None` and an
    /// undeclared default as the empty URI. The `xml` prefix is never
    /// listed: Canonical XML 1.0 sec.2.3 omits its namespace node.
    fn in_scope(&self) -> Vec<(Option<&'a str>, &'a str)> {
        let mut scope: Vec<(Option<&'a str>, &'a str)> = Vec::new();
        let mut current = Some(*self);
        while let Some(element) = current {
            for declaration in &element.data().declarations {
                let prefix = declaration.prefix.as_deref();
                if !scope.iter().any(|(seen, _)| *seen == prefix) {
                    scope.push((prefix, declaration.uri.as_str()));
                }
            }
            current = element.parent();
        }
        scope
    }

    /// The `xml:` attributes this element renders from its omitted
    /// ancestors when it is the apex of the subset, in place of or
    /// beside its own.
    ///
    /// Canonical XML 1.0 sec.2.4: every attribute in the XML namespace
    /// nearest along the ancestor axis that the element does not carry
    /// itself. Canonical XML 1.1 sec.2.4: only the simple inheritable
    /// `xml:lang` and `xml:space` that way, `xml:id` never, and
    /// `xml:base` fixed up by joining the omitted ancestors' values with
    /// the element's own. Exclusive XML Canonicalization 1.0 sec.3:
    /// none.
    fn inherited_xml_attributes(&self, algorithm: &Algorithm) -> InheritedXml {
        let mut inherited = InheritedXml::default();
        let own = |local: &str| {
            self.data()
                .attributes
                .iter()
                .any(|attribute| attribute.is_xml(local))
        };
        let mut ancestors = Vec::new();
        let mut current = self.parent();
        while let Some(ancestor) = current {
            ancestors.push(ancestor);
            current = ancestor.parent();
        }
        match algorithm {
            Algorithm::Exclusive(_) => {}
            Algorithm::Canonical10 => {
                for ancestor in &ancestors {
                    for attribute in &ancestor.data().attributes {
                        if attribute.namespace.as_deref() == Some(NAMESPACE_XML)
                            && !own(&attribute.local)
                            && !inherited
                                .added
                                .iter()
                                .any(|added| added.local == attribute.local)
                        {
                            inherited.added.push(attribute.clone());
                        }
                    }
                }
            }
            Algorithm::Canonical11 => {
                for local in SIMPLE_INHERITABLE {
                    if own(local) {
                        continue;
                    }
                    if let Some(attribute) = ancestors.iter().find_map(|ancestor| {
                        ancestor
                            .data()
                            .attributes
                            .iter()
                            .find(|attribute| attribute.is_xml(local))
                    }) {
                        inherited.added.push(attribute.clone());
                    }
                }
                // Outermost first, the element's own value last.
                let mut bases: Vec<&str> = ancestors
                    .iter()
                    .rev()
                    .filter_map(|ancestor| ancestor.xml_attribute(XML_BASE))
                    .collect();
                if !bases.is_empty() {
                    bases.extend(self.xml_attribute(XML_BASE));
                    let joined = bases
                        .iter()
                        .rev()
                        .copied()
                        .map(str::to_owned)
                        .reduce(|reference, base| join_uri_references(&base, &reference))
                        .unwrap_or_default();
                    inherited.base = Some(joined);
                }
            }
        }
        inherited
    }

    /// The value of this element's own `xml:` attribute `local`.
    fn xml_attribute(&self, local: &str) -> Option<&'a str> {
        self.data()
            .attributes
            .iter()
            .find(|attribute| attribute.is_xml(local))
            .map(|attribute| attribute.value.as_str())
    }

    /// The namespace declarations this element renders: for each
    /// prefix it must render, the URI in scope here, when it differs
    /// from the one in effect from its nearest output ancestor.
    ///
    /// Exclusive XML Canonicalization 1.0 sec.3 renders the prefixes
    /// the element visibly utilises -- its own, and those of its
    /// prefixed attributes; an unprefixed attribute is in no namespace
    /// and uses none -- and sec.4 adds the `PrefixList` prefixes.
    /// Canonical XML 1.0 and 1.1 sec.2.3 render every namespace in
    /// scope that the output parent does not already carry with the
    /// same value, and `xmlns=""` when the output parent has a default
    /// and this element has none.
    fn declarations_to_render(
        &self,
        rendered: &[(String, String)],
        algorithm: &Algorithm,
    ) -> Vec<(String, String)> {
        let data = self.data();
        let mut candidates: Vec<Option<&str>> = Vec::new();
        match algorithm {
            Algorithm::Exclusive(inclusive) => {
                candidates.push(data.prefix.as_deref());
                for attribute in &data.attributes {
                    if let Some(prefix) = attribute.prefix.as_deref()
                        && !candidates.contains(&Some(prefix))
                    {
                        candidates.push(Some(prefix));
                    }
                }
                for listed in &inclusive.prefixes {
                    let prefix = (!listed.is_empty()).then_some(listed.as_str());
                    if !candidates.contains(&prefix) {
                        candidates.push(prefix);
                    }
                }
            }
            Algorithm::Canonical10 | Algorithm::Canonical11 => {
                candidates.push(None);
                for (prefix, _uri) in self.in_scope() {
                    if !candidates.contains(&prefix) {
                        candidates.push(prefix);
                    }
                }
            }
        }
        let mut declarations: Vec<(String, String)> = Vec::new();
        for prefix in candidates {
            if prefix == Some(PREFIX_XML) {
                continue;
            }
            let key = prefix.unwrap_or_default();
            let uri = self.resolve(prefix).unwrap_or_default();
            let in_effect = rendered
                .iter()
                .rev()
                .find(|(rendered_prefix, _)| rendered_prefix == key)
                .map_or("", |(_, rendered_uri)| rendered_uri.as_str());
            if uri != in_effect {
                declarations.push((key.to_owned(), uri.to_owned()));
            }
        }
        // Namespace nodes sort by local name, the default first
        // (Canonical XML 1.0 sec.2.2 document order).
        declarations.sort();
        declarations
    }

    /// Render this element into `out`. `rendered` holds the namespace
    /// declarations in effect from output ancestors, innermost last,
    /// with the empty string standing for the default prefix.
    /// `inherited` holds the `xml:` attributes the apex takes from its
    /// omitted ancestors; it is empty below the apex, whose parent is
    /// always in the output.
    fn render(
        &self,
        out: &mut String,
        rendered: &mut Vec<(String, String)>,
        method: &Canonicalization,
        inherited: &InheritedXml,
    ) {
        let data = self.data();
        let scope_depth = rendered.len();
        let declarations = self.declarations_to_render(rendered, &method.algorithm);

        let mut attributes: Vec<&Attribute> = data
            .attributes
            .iter()
            .filter(|attribute| inherited.base.is_none() || !attribute.is_xml(XML_BASE))
            .chain(&inherited.added)
            .collect();
        let fixed_base = inherited
            .base
            .as_deref()
            .filter(|base| !base.is_empty())
            .map(|base| Attribute {
                prefix: Some(PREFIX_XML.to_owned()),
                local: XML_BASE.to_owned(),
                namespace: Some(NAMESPACE_XML.to_owned()),
                value: base.to_owned(),
            });
        attributes.extend(fixed_base.as_ref());
        // Attribute nodes sort by namespace URI, then local name; an
        // attribute in no namespace has the empty URI and sorts first.
        attributes.sort_by(|left, right| {
            (left.namespace.as_deref().unwrap_or_default(), &left.local)
                .cmp(&(right.namespace.as_deref().unwrap_or_default(), &right.local))
        });

        out.push('<');
        push_qualified_name(out, data.prefix.as_deref(), &data.local);
        for (prefix, uri) in &declarations {
            out.push(' ');
            out.push_str(PREFIX_XMLNS);
            if !prefix.is_empty() {
                out.push(':');
                out.push_str(prefix);
            }
            out.push_str("=\"");
            escape_attribute_into(out, uri);
            out.push('"');
        }
        for attribute in attributes {
            out.push(' ');
            push_qualified_name(out, attribute.prefix.as_deref(), &attribute.local);
            out.push_str("=\"");
            escape_attribute_into(out, &attribute.value);
            out.push('"');
        }
        out.push('>');
        rendered.extend(declarations);

        let below_apex = InheritedXml::default();
        for node in &data.children {
            match node {
                Node::Element(index) => {
                    if let Some(child) = self.document.element(*index) {
                        child.render(out, rendered, method, &below_apex);
                    }
                }
                Node::Text(text) => escape_text_into(out, text),
                Node::Comment(text) => {
                    if method.comments == Comments::Retained {
                        out.push_str(COMMENT_OPEN);
                        out.push_str(text);
                        out.push_str(COMMENT_CLOSE);
                    }
                }
                Node::ProcessingInstruction { target, data } => {
                    out.push_str(PI_OPEN);
                    out.push_str(target);
                    if !data.is_empty() {
                        out.push(' ');
                        out.push_str(data);
                    }
                    out.push_str(PI_CLOSE);
                }
            }
        }

        out.push_str(END_TAG_OPEN);
        push_qualified_name(out, data.prefix.as_deref(), &data.local);
        out.push('>');
        rendered.truncate(scope_depth);
    }
}

/// The prefixes an `InclusiveNamespaces PrefixList` names
/// (xml-exc-c14n sec.4), the default namespace as the empty string.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InclusivePrefixes {
    /// The named prefixes; the empty string is `#default`.
    prefixes: Vec<String>,
}

impl InclusivePrefixes {
    /// The prefixes a `PrefixList` attribute value names: tokens
    /// separated by white space, each `#default` or a prefix without a
    /// colon. `None` for any other token.
    #[must_use]
    pub fn parse(list: &str) -> Option<Self> {
        let mut prefixes = Vec::new();
        for token in list.split(|character: char| XML_WHITE_SPACE.contains(&character)) {
            if token.is_empty() {
                continue;
            }
            let prefix = if token == PREFIX_LIST_DEFAULT {
                String::new()
            } else if token.contains(':') || token.starts_with('#') {
                return None;
            } else {
                token.to_owned()
            };
            if !prefixes.contains(&prefix) {
                prefixes.push(prefix);
            }
        }
        Some(Self { prefixes })
    }
}

/// The `PrefixList` token naming the default namespace (xml-exc-c14n
/// sec.4).
const PREFIX_LIST_DEFAULT: &str = "#default";

/// XML white space (XML 1.0 sec.2.3 production 3).
const XML_WHITE_SPACE: [char; 4] = [' ', '\t', '\n', '\r'];

/// Append `prefix:local`, or `local` alone.
fn push_qualified_name(out: &mut String, prefix: Option<&str>, local: &str) {
    if let Some(prefix) = prefix {
        out.push_str(prefix);
        out.push(':');
    }
    out.push_str(local);
}

/// Escape an attribute value as Canonical XML 1.0 sec.2.3 writes it:
/// `&`, `<`, `"`, TAB, LF and CR.
fn escape_attribute_into(out: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
}

/// Escape character data as Canonical XML 1.0 sec.2.3 writes it: `&`,
/// `<`, `>` and CR.
fn escape_text_into(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
}

/// A URI reference split as RFC 3986 appendix B splits it, the
/// fragment dropped.
struct UriParts<'a> {
    /// The scheme, without its colon.
    scheme: Option<&'a str>,
    /// The authority, without its leading slashes.
    authority: Option<&'a str>,
    /// The path, possibly empty.
    path: &'a str,
    /// The query, without its question mark.
    query: Option<&'a str>,
}

impl<'a> UriParts<'a> {
    /// Split `reference`.
    fn split(reference: &'a str) -> Self {
        let reference = reference
            .split_once('#')
            .map_or(reference, |(before, _fragment)| before);
        let (scheme, rest) = match reference.find([':', '/', '?']) {
            Some(colon)
                if colon > 0
                    && reference
                        .get(colon..)
                        .is_some_and(|tail| tail.starts_with(':')) =>
            {
                (
                    reference.get(..colon),
                    reference.get(colon.saturating_add(1)..).unwrap_or_default(),
                )
            }
            _ => (None, reference),
        };
        let (authority, rest) = match rest.strip_prefix("//") {
            Some(after) => {
                let end = after.find(['/', '?']).unwrap_or(after.len());
                (after.get(..end), after.get(end..).unwrap_or_default())
            }
            None => (None, rest),
        };
        let (path, query) = match rest.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (rest, None),
        };
        Self {
            scheme,
            authority,
            path,
            query,
        }
    }
}

/// The `join-URI-References` function of Canonical XML 1.1 sec.2.4:
/// `reference` resolved against `base` as RFC 3986 sec.5.2.2 resolves
/// it, with the fragment ignored, a scheme not required in `base`, a
/// trailing `..` segment of `base` read as `../`, and dot segments
/// removed by [`remove_dot_segments`], which keeps a relative path
/// relative.
fn join_uri_references(base: &str, reference: &str) -> String {
    let base_parts = UriParts::split(base);
    let reference_parts = UriParts::split(reference);
    let base_path = if base_parts.path == DOT_DOT || base_parts.path.ends_with("/..") {
        format!("{}/", base_parts.path)
    } else {
        base_parts.path.to_owned()
    };
    let (scheme, authority, path, query) = if reference_parts.scheme.is_some() {
        (
            reference_parts.scheme,
            reference_parts.authority,
            remove_dot_segments(reference_parts.path),
            reference_parts.query,
        )
    } else if reference_parts.authority.is_some() {
        (
            base_parts.scheme,
            reference_parts.authority,
            remove_dot_segments(reference_parts.path),
            reference_parts.query,
        )
    } else if reference_parts.path.is_empty() {
        (
            base_parts.scheme,
            base_parts.authority,
            base_path,
            reference_parts.query.or(base_parts.query),
        )
    } else if reference_parts.path.starts_with('/') {
        (
            base_parts.scheme,
            base_parts.authority,
            remove_dot_segments(reference_parts.path),
            reference_parts.query,
        )
    } else {
        // RFC 3986 sec.5.2.3: merge the paths.
        let merged = if base_parts.authority.is_some() && base_path.is_empty() {
            format!("/{}", reference_parts.path)
        } else {
            match base_path.rfind('/') {
                Some(slash) => format!(
                    "{}{}",
                    base_path.get(..=slash).unwrap_or_default(),
                    reference_parts.path
                ),
                None => reference_parts.path.to_owned(),
            }
        };
        (
            base_parts.scheme,
            base_parts.authority,
            remove_dot_segments(&merged),
            reference_parts.query,
        )
    };
    // RFC 3986 sec.5.3: recompose, without a fragment.
    let mut out = String::new();
    if let Some(scheme) = scheme {
        out.push_str(scheme);
        out.push(':');
    }
    if let Some(authority) = authority {
        out.push_str("//");
        out.push_str(authority);
    }
    out.push_str(&path);
    if let Some(query) = query {
        out.push('?');
        out.push_str(query);
    }
    out
}

/// The `..` path segment (RFC 3986 sec.3.3).
const DOT_DOT: &str = "..";

/// The `.` path segment.
const DOT: &str = ".";

/// RFC 3986 sec.5.2.4 "Remove Dot Segments" as Canonical XML 1.1
/// sec.2.4 modifies it: leading `../` segments of a relative path are
/// kept, consecutive slashes collapse into one, and a trailing `..`
/// gains a slash.
fn remove_dot_segments(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut kept: Vec<&str> = Vec::new();
    let mut trailing_slash = false;
    for segment in path.split('/') {
        trailing_slash = false;
        match segment {
            "" => trailing_slash = true,
            DOT => trailing_slash = true,
            DOT_DOT => {
                trailing_slash = true;
                match kept.last() {
                    Some(&last) if last != DOT_DOT => {
                        kept.pop();
                    }
                    _ if !absolute => kept.push(DOT_DOT),
                    _ => {}
                }
            }
            other => kept.push(other),
        }
    }
    let mut out = String::new();
    if absolute {
        out.push('/');
    }
    out.push_str(&kept.join("/"));
    if trailing_slash && !kept.is_empty() {
        out.push('/');
    }
    out
}

/// Why a document declaring a relative namespace URI is refused.
const RELATIVE_NAMESPACE: &str = "relative namespace URI";

/// Whether `uri` is absolute: it opens with a scheme, a letter then
/// letters, digits, `+`, `-` or `.`, and a colon (RFC 3986 sec.3.1).
/// Canonical XML 1.0 sec.2.1 requires canonicalisation to fail on a
/// document with a relative namespace URI, so the reader refuses one
/// and no canonicalisation ever meets it.
fn is_absolute_uri(uri: &str) -> bool {
    let Some((scheme, _rest)) = uri.split_once(':') else {
        return false;
    };
    let mut characters = scheme.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
}

/// Whether `character` is an XML `Char` (XML 1.0 sec.2.2 production 2).
fn is_xml_char(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\r')
        || (CHAR_RANGE_1_START..=CHAR_RANGE_1_END).contains(&character)
        || (CHAR_RANGE_2_START..=CHAR_RANGE_2_END).contains(&character)
        || character >= CHAR_RANGE_3_START
}

/// Whether `character` may start an `NCName` (Namespaces in XML 1.0
/// sec.3 over XML 1.0 sec.2.3 `NameStartChar`, colon excluded). Every
/// non-ASCII character is accepted; the ASCII subset is exact.
const fn is_name_start(character: char) -> bool {
    character.is_ascii_alphabetic() || character == '_' || !character.is_ascii()
}

/// Whether `character` may continue an `NCName`.
const fn is_name_char(character: char) -> bool {
    is_name_start(character) || character.is_ascii_digit() || matches!(character, '-' | '.')
}

/// A name as written: optional prefix and local part.
struct QualifiedName {
    /// The part before the colon.
    prefix: Option<String>,
    /// The part after it, or the whole name.
    local: String,
}

/// An attribute as written, before namespace resolution.
struct RawAttribute {
    /// The name.
    name: QualifiedName,
    /// The normalised value.
    value: String,
}

/// The parser state: the source and the position in it.
struct Parser<'a> {
    /// The whole source.
    text: &'a str,
    /// The byte offset of the next unread character.
    position: usize,
    /// The elements parsed so far.
    elements: Vec<ElementData>,
    /// The open elements, innermost last.
    open: Vec<usize>,
    /// Every `Id` attribute value seen so far.
    ids: std::collections::HashSet<String>,
    /// Nodes created so far, bounded by [`MAX_NODES`].
    nodes: usize,
}

impl<'a> Parser<'a> {
    /// A parser at the start of `text`.
    fn new(text: &'a str) -> Self {
        Self {
            text,
            position: 0,
            elements: Vec::new(),
            open: Vec::new(),
            nodes: 0,
            ids: std::collections::HashSet::new(),
        }
    }

    /// The unread text.
    fn rest(&self) -> &'a str {
        self.text.get(self.position..).unwrap_or_default()
    }

    /// The next unread character.
    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    /// Whether the unread text starts with `token`.
    fn at(&self, token: &str) -> bool {
        self.rest().starts_with(token)
    }

    /// Consume `token` if the unread text starts with it.
    fn eat(&mut self, token: &str) -> bool {
        if self.at(token) {
            self.position = self.position.saturating_add(token.len());
            true
        } else {
            false
        }
    }

    /// Consume `token` or fail with `what`.
    fn expect(&mut self, token: &str, what: &'static str) -> Result<(), XmlError> {
        if self.eat(token) {
            Ok(())
        } else {
            Err(XmlError::Malformed(what))
        }
    }

    /// Consume one character.
    fn bump(&mut self) -> Option<char> {
        let character = self.peek()?;
        self.position = self.position.saturating_add(character.len_utf8());
        Some(character)
    }

    /// Consume XML whitespace (XML 1.0 sec.2.3 production 3); report
    /// whether there was any.
    fn skip_whitespace(&mut self) -> bool {
        let start = self.position;
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.position = self.position.saturating_add(1);
        }
        self.position != start
    }

    /// Consume the text up to `close` and `close` itself, returning
    /// the text.
    fn until(&mut self, close: &str, what: &'static str) -> Result<&'a str, XmlError> {
        let rest = self.rest();
        let end = rest.find(close).ok_or(XmlError::Malformed(what))?;
        let body = rest.get(..end).ok_or(XmlError::Malformed(what))?;
        self.position = self
            .position
            .saturating_add(end)
            .saturating_add(close.len());
        if !body.chars().all(is_xml_char) {
            return Err(XmlError::Malformed("character outside the XML Char set"));
        }
        Ok(body)
    }

    /// The whole document: prolog, one element, trailing misc.
    fn document(mut self) -> Result<Vec<ElementData>, XmlError> {
        if self.peek() == Some(BYTE_ORDER_MARK) {
            self.bump();
        }
        if self.at(XML_DECLARATION_OPEN)
            && self
                .rest()
                .get(XML_DECLARATION_OPEN.len()..)
                .and_then(|after| after.chars().next())
                .is_some_and(|character| matches!(character, ' ' | '\t' | '\n' | '\r'))
        {
            self.xml_declaration()?;
        }
        self.misc()?;
        if self.at(DOCTYPE_OPEN) {
            return Err(XmlError::Unsupported("document type declaration"));
        }
        if self.peek() != Some('<') {
            return Err(XmlError::Malformed("no document element"));
        }
        self.content()?;
        self.misc()?;
        if self.position != self.text.len() {
            return Err(XmlError::Malformed("content after the document element"));
        }
        Ok(self.elements)
    }

    /// The XML declaration: version and an encoding, when named, of
    /// UTF-8 (XML 1.0 sec.2.8 and sec.4.3.3).
    fn xml_declaration(&mut self) -> Result<(), XmlError> {
        self.expect(XML_DECLARATION_OPEN, "XML declaration")?;
        let body = self.until(PI_CLOSE, "unterminated XML declaration")?;
        let mut declaration = Parser::new(body);
        let mut first = true;
        loop {
            let spaced = declaration.skip_whitespace();
            if declaration.position == body.len() {
                break;
            }
            if !spaced {
                return Err(XmlError::Malformed("XML declaration"));
            }
            let name = declaration.name_token()?;
            declaration.skip_whitespace();
            declaration.expect("=", "XML declaration")?;
            declaration.skip_whitespace();
            let value = declaration.quoted_literal()?;
            match name {
                "version" if first => {}
                "encoding" if !first => {
                    if !value.eq_ignore_ascii_case(ENCODING_UTF8) {
                        return Err(XmlError::Unsupported("an encoding other than UTF-8"));
                    }
                }
                "standalone" if !first => {}
                _ => return Err(XmlError::Malformed("XML declaration")),
            }
            first = false;
        }
        if first {
            return Err(XmlError::Malformed("XML declaration without a version"));
        }
        Ok(())
    }

    /// A quoted literal with no references, for the XML declaration.
    fn quoted_literal(&mut self) -> Result<&'a str, XmlError> {
        let quote = self.bump().ok_or(XmlError::Malformed("missing quote"))?;
        let close = match quote {
            '"' => "\"",
            '\'' => "'",
            _ => return Err(XmlError::Malformed("missing quote")),
        };
        self.until(close, "unterminated literal")
    }

    /// A run of name characters, colons included.
    fn name_token(&mut self) -> Result<&'a str, XmlError> {
        let start = self.position;
        match self.peek() {
            Some(character) if is_name_start(character) => {
                self.bump();
            }
            _ => return Err(XmlError::Malformed("name expected")),
        }
        while self
            .peek()
            .is_some_and(|character| is_name_char(character) || character == ':')
        {
            self.bump();
        }
        self.text
            .get(start..self.position)
            .ok_or(XmlError::Malformed("name expected"))
    }

    /// A `QName` (Namespaces in XML 1.0 sec.4): one optional prefix and
    /// a local part, both `NCName`s.
    fn qualified_name(&mut self) -> Result<QualifiedName, XmlError> {
        let token = self.name_token()?;
        let mut parts = token.split(':');
        let (Some(first), second, None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(XmlError::Malformed("name with more than one colon"));
        };
        let valid = |part: &str| part.chars().next().is_some_and(is_name_start);
        match second {
            None => Ok(QualifiedName {
                prefix: None,
                local: first.to_owned(),
            }),
            Some(local) if valid(first) && valid(local) => Ok(QualifiedName {
                prefix: Some(first.to_owned()),
                local: local.to_owned(),
            }),
            Some(_) => Err(XmlError::Malformed("empty name part")),
        }
    }

    /// Comments, processing instructions and whitespace outside the
    /// document element.
    fn misc(&mut self) -> Result<(), XmlError> {
        loop {
            self.skip_whitespace();
            if self.eat(COMMENT_OPEN) {
                self.comment_body()?;
            } else if self.at(PI_OPEN) {
                self.processing_instruction()?;
            } else {
                return Ok(());
            }
        }
    }

    /// The rest of a comment after its opening; `--` may not occur in
    /// it (XML 1.0 sec.2.5).
    fn comment_body(&mut self) -> Result<String, XmlError> {
        let body = self.until(COMMENT_CLOSE, "unterminated comment")?;
        if body.contains("--") || body.ends_with('-') {
            return Err(XmlError::Malformed("double hyphen in a comment"));
        }
        Ok(normalise_line_ends(body))
    }

    /// A processing instruction; its target may not be `xml` in any
    /// case (XML 1.0 sec.2.6).
    fn processing_instruction(&mut self) -> Result<Node, XmlError> {
        self.expect(PI_OPEN, "processing instruction")?;
        let target = self.name_token()?;
        if target.eq_ignore_ascii_case(PREFIX_XML) {
            return Err(XmlError::Malformed("misplaced XML declaration"));
        }
        if target.contains(':') {
            return Err(XmlError::Malformed(
                "colon in a processing instruction target",
            ));
        }
        let spaced = self.skip_whitespace();
        let data = self.until(PI_CLOSE, "unterminated processing instruction")?;
        if !spaced && !data.is_empty() {
            return Err(XmlError::Malformed("processing instruction target"));
        }
        Ok(Node::ProcessingInstruction {
            target: target.to_owned(),
            data: normalise_line_ends(data),
        })
    }

    /// The document element and everything inside it.
    fn content(&mut self) -> Result<(), XmlError> {
        self.start_tag()?;
        while let Some(&current) = self.open.last() {
            if self.eat(END_TAG_OPEN) {
                self.end_tag(current)?;
            } else if self.eat(COMMENT_OPEN) {
                let text = self.comment_body()?;
                self.push_node(current, Node::Comment(text))?;
            } else if self.eat(CDATA_OPEN) {
                let text = normalise_line_ends(self.until(CDATA_CLOSE, "unterminated CDATA")?);
                self.push_text(current, &text)?;
            } else if self.at(DOCTYPE_OPEN) {
                return Err(XmlError::Unsupported("document type declaration"));
            } else if self.at(PI_OPEN) {
                let node = self.processing_instruction()?;
                self.push_node(current, node)?;
            } else if self.at("<") {
                self.start_tag()?;
            } else {
                let text = self.character_data()?;
                self.push_text(current, &text)?;
            }
        }
        Ok(())
    }

    /// Character data up to the next markup.
    fn character_data(&mut self) -> Result<String, XmlError> {
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(XmlError::Malformed("unterminated element")),
                Some('<') => return Ok(out),
                Some('&') => out.push(self.reference()?),
                Some('\r') => {
                    self.bump();
                    self.eat("\n");
                    out.push('\n');
                }
                Some(_) => {
                    if self.at(CDATA_CLOSE) {
                        return Err(XmlError::Malformed("]]> in character data"));
                    }
                    let character = self.bump().ok_or(XmlError::Malformed("truncated"))?;
                    if !is_xml_char(character) {
                        return Err(XmlError::Malformed("character outside the XML Char set"));
                    }
                    out.push(character);
                }
            }
        }
    }

    /// A reference starting at `&` (XML 1.0 sec.4.1): one of the five
    /// predefined entities or a character reference.
    fn reference(&mut self) -> Result<char, XmlError> {
        self.expect("&", "reference")?;
        let body = self.until(";", "unterminated reference")?;
        let resolved = match body {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => {
                if let Some(digits) = body.strip_prefix(CHAR_REF_HEX) {
                    character_reference(digits, RADIX_HEX)
                } else if let Some(digits) = body.strip_prefix(CHAR_REF_DECIMAL) {
                    character_reference(digits, RADIX_DECIMAL)
                } else {
                    return Err(XmlError::Unsupported("entity reference"));
                }
            }
        };
        resolved.ok_or(XmlError::Malformed("character reference"))
    }

    /// Count one more node against [`MAX_NODES`].
    fn count_node(&mut self) -> Result<(), XmlError> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_NODES {
            return Err(XmlError::TooManyNodes);
        }
        Ok(())
    }

    /// Append `node` to the children of the element at `parent`.
    fn push_node(&mut self, parent: usize, node: Node) -> Result<(), XmlError> {
        self.count_node()?;
        if let Some(element) = self.elements.get_mut(parent) {
            element.children.push(node);
        }
        Ok(())
    }

    /// Append character data to `parent`, merging with a preceding
    /// text child.
    fn push_text(&mut self, parent: usize, text: &str) -> Result<(), XmlError> {
        if text.is_empty() {
            return Ok(());
        }
        let merges = self
            .elements
            .get(parent)
            .is_some_and(|element| matches!(element.children.last(), Some(Node::Text(_))));
        if !merges {
            self.count_node()?;
        }
        if let Some(element) = self.elements.get_mut(parent) {
            if let Some(Node::Text(previous)) = element.children.last_mut() {
                previous.push_str(text);
            } else {
                element.children.push(Node::Text(text.to_owned()));
            }
        }
        Ok(())
    }

    /// A start tag or empty-element tag at `<`.
    fn start_tag(&mut self) -> Result<(), XmlError> {
        if self.open.len() >= MAX_DEPTH {
            return Err(XmlError::TooDeep);
        }
        self.count_node()?;
        let start = self.position;
        self.expect("<", "start tag")?;
        let name = self.qualified_name()?;
        let mut raw = Vec::new();
        let empty = loop {
            let spaced = self.skip_whitespace();
            if self.eat(EMPTY_TAG_CLOSE) {
                break true;
            }
            if self.eat(">") {
                break false;
            }
            if !spaced {
                return Err(XmlError::Malformed(
                    "attributes must be separated by whitespace",
                ));
            }
            let attribute_name = self.qualified_name()?;
            self.skip_whitespace();
            self.expect("=", "attribute without a value")?;
            self.skip_whitespace();
            let value = self.attribute_value()?;
            raw.push(RawAttribute {
                name: attribute_name,
                value,
            });
        };

        let index = self.elements.len();
        let parent = self.open.last().copied();
        let mut declarations = Vec::new();
        let mut plain = Vec::new();
        for attribute in raw {
            match (
                attribute.name.prefix.as_deref(),
                attribute.name.local.as_str(),
            ) {
                (None, PREFIX_XMLNS) => {
                    if attribute.value == NAMESPACE_XML || attribute.value == NAMESPACE_XMLNS {
                        return Err(XmlError::Malformed("reserved namespace as the default"));
                    }
                    if !attribute.value.is_empty() && !is_absolute_uri(&attribute.value) {
                        return Err(XmlError::Malformed(RELATIVE_NAMESPACE));
                    }
                    declarations.push(Declaration {
                        prefix: None,
                        uri: attribute.value,
                    });
                }
                (Some(PREFIX_XMLNS), PREFIX_XML) => {
                    if attribute.value != NAMESPACE_XML {
                        return Err(XmlError::Malformed("xml prefix rebound"));
                    }
                }
                (Some(PREFIX_XMLNS), PREFIX_XMLNS) => {
                    return Err(XmlError::Malformed("xmlns prefix declared"));
                }
                (Some(PREFIX_XMLNS), prefix) => {
                    if attribute.value.is_empty() {
                        return Err(XmlError::Malformed("prefix undeclared"));
                    }
                    if attribute.value == NAMESPACE_XML || attribute.value == NAMESPACE_XMLNS {
                        return Err(XmlError::Malformed("reserved namespace bound to a prefix"));
                    }
                    if !is_absolute_uri(&attribute.value) {
                        return Err(XmlError::Malformed(RELATIVE_NAMESPACE));
                    }
                    declarations.push(Declaration {
                        prefix: Some(prefix.to_owned()),
                        uri: attribute.value,
                    });
                }
                _ => plain.push(attribute),
            }
        }
        for (position, declaration) in declarations.iter().enumerate() {
            if declarations
                .iter()
                .skip(position.saturating_add(1))
                .any(|other| other.prefix == declaration.prefix)
            {
                return Err(XmlError::Malformed("duplicate namespace declaration"));
            }
        }
        if name.prefix.as_deref() == Some(PREFIX_XMLNS) {
            return Err(XmlError::Malformed("element in the xmlns namespace"));
        }

        self.elements.push(ElementData {
            prefix: name.prefix,
            local: name.local,
            namespace: None,
            attributes: Vec::new(),
            declarations,
            children: Vec::new(),
            parent,
            span: start..start,
        });
        let resolver = ResolveAt {
            elements: &self.elements,
            index,
        };
        let element_prefix = self
            .elements
            .get(index)
            .and_then(|element| element.prefix.clone());
        let namespace = match element_prefix.as_deref() {
            None => resolver.resolve(None).map(str::to_owned),
            Some(prefix) => Some(
                resolver
                    .resolve(Some(prefix))
                    .ok_or(XmlError::Malformed("undeclared element prefix"))?
                    .to_owned(),
            ),
        };
        let mut attributes: Vec<Attribute> = Vec::with_capacity(plain.len());
        for attribute in plain {
            let attribute_namespace = match attribute.name.prefix.as_deref() {
                None => None,
                Some(prefix) => Some(
                    resolver
                        .resolve(Some(prefix))
                        .ok_or(XmlError::Malformed("undeclared attribute prefix"))?
                        .to_owned(),
                ),
            };
            if attributes.iter().any(|existing| {
                existing.local == attribute.name.local && existing.namespace == attribute_namespace
            }) {
                return Err(XmlError::Malformed("duplicate attribute"));
            }
            if attribute_namespace.is_none()
                && attribute.name.local == ATTRIBUTE_ID
                && !self.ids.insert(attribute.value.clone())
            {
                return Err(XmlError::Malformed("duplicate Id"));
            }
            attributes.push(Attribute {
                prefix: attribute.name.prefix,
                local: attribute.name.local,
                namespace: attribute_namespace,
                value: attribute.value,
            });
        }
        if let Some(element) = self.elements.get_mut(index) {
            element.namespace = namespace;
            element.attributes = attributes;
            element.span = start..self.position;
        }
        // The element was counted when its start tag opened.
        if let Some(parent) = parent
            && let Some(element) = self.elements.get_mut(parent)
        {
            element.children.push(Node::Element(index));
        }
        if !empty {
            self.open.push(index);
        }
        Ok(())
    }

    /// An end tag after its `</`, which must name the open element.
    fn end_tag(&mut self, current: usize) -> Result<(), XmlError> {
        let name = self.qualified_name()?;
        self.skip_whitespace();
        self.expect(">", "unterminated end tag")?;
        let end = self.position;
        let element = self
            .elements
            .get_mut(current)
            .ok_or(XmlError::Malformed("end tag without a start tag"))?;
        if element.prefix != name.prefix || element.local != name.local {
            return Err(XmlError::Malformed("end tag does not match the start tag"));
        }
        element.span.end = end;
        self.open.pop();
        Ok(())
    }

    /// A quoted attribute value, normalised as XML 1.0 sec.3.3.3 does
    /// for `CDATA`: each literal whitespace character becomes a space,
    /// a CR LF pair one space, and references are resolved without
    /// normalisation.
    fn attribute_value(&mut self) -> Result<String, XmlError> {
        let quote = self
            .bump()
            .ok_or(XmlError::Malformed("attribute value expected"))?;
        if quote != '"' && quote != '\'' {
            return Err(XmlError::Malformed("attribute value must be quoted"));
        }
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(XmlError::Malformed("unterminated attribute value")),
                Some(character) if character == quote => {
                    self.bump();
                    return Ok(out);
                }
                Some('<') => return Err(XmlError::Malformed("< in an attribute value")),
                Some('&') => out.push(self.reference()?),
                Some('\r') => {
                    self.bump();
                    self.eat("\n");
                    out.push(' ');
                }
                Some('\n' | '\t') => {
                    self.bump();
                    out.push(' ');
                }
                Some(_) => {
                    let character = self.bump().ok_or(XmlError::Malformed("truncated"))?;
                    if !is_xml_char(character) {
                        return Err(XmlError::Malformed("character outside the XML Char set"));
                    }
                    out.push(character);
                }
            }
        }
    }
}

/// Namespace resolution over the elements parsed so far.
struct ResolveAt<'a> {
    /// The element arena.
    elements: &'a [ElementData],
    /// The element resolution starts at.
    index: usize,
}

impl<'a> ResolveAt<'a> {
    /// What `prefix` resolves to at the element: its declarations, then
    /// its ancestors'.
    fn resolve(&self, prefix: Option<&str>) -> Option<&'a str> {
        if prefix == Some(PREFIX_XML) {
            return Some(NAMESPACE_XML);
        }
        let mut current = Some(self.index);
        while let Some(index) = current {
            let element = self.elements.get(index)?;
            if let Some(declaration) = element
                .declarations
                .iter()
                .find(|declaration| declaration.prefix.as_deref() == prefix)
            {
                return if declaration.uri.is_empty() {
                    None
                } else {
                    Some(declaration.uri.as_str())
                };
            }
            current = element.parent;
        }
        None
    }
}

/// Resolve the digits of a character reference to a `Char`.
fn character_reference(digits: &str, radix: u32) -> Option<char> {
    if digits.is_empty() || !digits.chars().all(|digit| digit.is_digit(radix)) {
        return None;
    }
    u32::from_str_radix(digits, radix)
        .ok()
        .and_then(char::from_u32)
        .filter(|character| is_xml_char(*character))
}

/// End-of-line handling (XML 1.0 sec.2.11): CR LF and a lone CR both
/// become LF.
fn normalise_line_ends(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

#[cfg(test)]
mod tests {
    use super::{
        Algorithm, Canonicalization, Comments, InclusivePrefixes, MAX_DEPTH, MAX_NODES,
        XmlDocument, XmlError, join_uri_references,
    };
    use crate::verification::exactly;

    fn parse(text: &str) -> XmlDocument {
        XmlDocument::parse(text.as_bytes().to_vec()).expect("parses")
    }

    fn refuse(text: &str) -> Option<XmlError> {
        XmlDocument::parse(text.as_bytes().to_vec()).err()
    }

    fn canonical(text: &str, comments: Comments) -> String {
        String::from_utf8(
            parse(text)
                .root()
                .canonicalize(&Canonicalization::exclusive(comments)),
        )
        .expect("utf-8")
    }

    /// `element` under `algorithm` without comments, as text.
    fn under(element: super::ElementRef<'_>, algorithm: Algorithm, comments: Comments) -> String {
        String::from_utf8(element.canonicalize(&Canonicalization {
            algorithm,
            comments,
        }))
        .expect("utf-8")
    }

    /// The first element of `document` named `local`.
    fn named<'a>(document: &'a XmlDocument, local: &str) -> super::ElementRef<'a> {
        document
            .elements()
            .find(|element| element.local_name() == local)
            .expect("element")
    }

    #[test]
    fn prefixes_resolve_through_declarations_in_scope() {
        let document = parse(r#"<a:x xmlns:a="urn:a" xmlns="urn:d"><y a:k="v"/><a:z/></a:x>"#);
        let root = document.root();
        assert!(root.is("urn:a", "x"));
        let children: Vec<_> = root.children().collect();
        let [y, z] = exactly(children.as_slice(), "two children");
        assert!(y.is("urn:d", "y"));
        assert!(z.is("urn:a", "z"));
        assert_eq!(y.attribute("k"), None, "a prefixed attribute is namespaced");
        assert_eq!(y.parent(), Some(root));
    }

    #[test]
    fn spans_cover_the_element_exactly() {
        let text = r#"<?xml version="1.0"?><r><c a="v">t</c><e/></r>"#;
        let document = parse(text);
        let spans: Vec<&str> = document
            .elements()
            .map(|element| &text[element.span()])
            .collect();
        assert_eq!(
            spans,
            [r#"<r><c a="v">t</c><e/></r>"#, r#"<c a="v">t</c>"#, "<e/>"]
        );
    }

    #[test]
    fn references_comments_and_cdata_are_resolved() {
        let document = parse("<r>&amp;&lt;&#x41;&#66;<!-- c --><![CDATA[<raw>]]>\r\n</r>");
        assert_eq!(document.root().text(), "&<AB<raw>\n");
    }

    #[test]
    fn exotic_constructs_are_refused() {
        assert_eq!(
            refuse("<!DOCTYPE r><r/>"),
            Some(XmlError::Unsupported("document type declaration"))
        );
        assert_eq!(
            refuse("<r><!DOCTYPE r></r>"),
            Some(XmlError::Unsupported("document type declaration"))
        );
        assert_eq!(
            refuse("<r>&custom;</r>"),
            Some(XmlError::Unsupported("entity reference"))
        );
        assert_eq!(
            refuse("<r a='&custom;'/>"),
            Some(XmlError::Unsupported("entity reference"))
        );
        assert!(matches!(
            refuse(r#"<?xml version="1.0" encoding="ISO-8859-1"?><r/>"#),
            Some(XmlError::Unsupported(_))
        ));
        for malformed in [
            "<p:r/>",
            "<r a='v' a='w'/>",
            "<r></s>",
            "<r/><s/>",
            "<r>]]></r>",
            "<r><!-- a -- b --></r>",
            "<r a=v/>",
            "<r xmlns:p=''/>",
            "<r xmlns:xmlns='urn:x'/>",
            "<r xmlns:xml='urn:x'/>",
            "<r xmlns='relative/path'/>",
            "<r xmlns:p='../up'/>",
            "<r xmlns:p='1urn:x'/>",
            "<r>&#0;</r>",
            "",
            "text",
        ] {
            assert!(
                matches!(refuse(malformed), Some(XmlError::Malformed(_))),
                "{malformed}"
            );
        }
        assert_eq!(
            XmlDocument::parse(vec![u8::MAX]).err(),
            Some(XmlError::NotUtf8)
        );
    }

    /// A relative namespace URI fails every canonicalisation (Canonical
    /// XML 1.0 sec.2.1), so the reader refuses the document; an absolute
    /// one and the undeclared default pass.
    #[test]
    fn a_relative_namespace_uri_is_refused() {
        assert_eq!(
            refuse("<r xmlns:p='relative'><p:c/></r>"),
            Some(XmlError::Malformed("relative namespace URI"))
        );
        assert_eq!(
            refuse("<r><c xmlns='#fragment'/></r>"),
            Some(XmlError::Malformed("relative namespace URI"))
        );
        for accepted in [
            "<r xmlns='urn:x' xmlns:p='http://example.org/p'><c xmlns=''/></r>",
            "<r xmlns:p='urn:example:p'/>",
        ] {
            assert!(
                XmlDocument::parse(accepted.as_bytes().to_vec()).is_ok(),
                "{accepted}"
            );
        }
    }

    #[test]
    fn a_repeated_id_is_refused() {
        assert_eq!(
            refuse(r#"<r><a Id="one"/><b Id="one"/></r>"#),
            Some(XmlError::Malformed("duplicate Id"))
        );
        let document = parse(r#"<r xmlns:p="urn:p"><a Id="one"/><b p:Id="one"/></r>"#);
        let ids: Vec<_> = document
            .elements()
            .filter_map(|element| element.attribute("Id"))
            .collect();
        assert_eq!(ids, ["one"], "a namespaced Id is another attribute");
    }

    #[test]
    fn nesting_is_bounded() {
        let at_bound = format!("{}{}", "<a>".repeat(MAX_DEPTH), "</a>".repeat(MAX_DEPTH));
        assert!(XmlDocument::parse(at_bound.into_bytes()).is_ok());
        let depth = MAX_DEPTH.saturating_add(1);
        let text = format!("{}{}", "<a>".repeat(depth), "</a>".repeat(depth));
        assert_eq!(
            XmlDocument::parse(text.into_bytes()).err(),
            Some(XmlError::TooDeep)
        );
    }

    /// Canonical XML 1.0 sec.3.2 and sec.3.3 in miniature: empty
    /// elements get end tags, attributes are sorted and requoted,
    /// values are normalised, and only the escapes c14n names remain.
    #[test]
    fn canonical_form_follows_canonical_xml_section_2_3() {
        assert_eq!(
            canonical(
                "<r b='w' a=\"x&#9;y\n z\" c='&apos;&gt;'><e/>a&gt;b&#13;</r>",
                Comments::Omitted
            ),
            "<r a=\"x&#x9;y  z\" b=\"w\" c=\"'>\"><e></e>a&gt;b&#xD;</r>"
        );
    }

    /// Namespaced attributes sort after unqualified ones, by URI then
    /// local name, whatever their prefixes.
    #[test]
    fn attributes_sort_by_namespace_uri_then_local_name() {
        assert_eq!(
            canonical(
                r#"<r xmlns:z="urn:a" xmlns:a="urn:b" a:x="u" z:y="v" b="w"/>"#,
                Comments::Omitted
            ),
            r#"<r xmlns:a="urn:b" xmlns:z="urn:a" b="w" z:y="v" a:x="u"></r>"#
        );
    }

    /// The exclusive rule: a declaration appears where the prefix is
    /// first visibly used, an unused one never, and one already in
    /// effect is not repeated.
    #[test]
    fn exclusive_canonicalisation_renders_declarations_where_used() {
        let document = parse(
            r#"<o xmlns:u="urn:unused" xmlns:a="urn:a" xmlns="urn:d"><a:x><a:y/><z/></a:x></o>"#,
        );
        let inner = document.root().children().next().expect("child");
        let bytes = inner.canonicalize(&Canonicalization::exclusive(Comments::Omitted));
        assert_eq!(
            String::from_utf8(bytes).expect("utf-8"),
            r#"<a:x xmlns:a="urn:a"><a:y></a:y><z xmlns="urn:d"></z></a:x>"#
        );
        assert_eq!(
            canonical(r#"<r xmlns="urn:d"><s xmlns=""/></r>"#, Comments::Omitted),
            r#"<r xmlns="urn:d"><s xmlns=""></s></r>"#
        );
    }

    /// `xml:` attributes are not inherited by an exclusive subset
    /// (xml-exc-c14n sec.3), and the `xml` prefix is never declared.
    #[test]
    fn xml_attributes_stay_where_they_are_written() {
        let document = parse(
            r#"<o xml:lang="fi" xml:base="urn:base" xml:space="default"><i xml:space="preserve"/></o>"#,
        );
        let inner = document.root().children().next().expect("child");
        assert_eq!(
            String::from_utf8(inner.canonicalize(&Canonicalization::exclusive(Comments::Omitted)))
                .expect("utf-8"),
            r#"<i xml:space="preserve"></i>"#
        );
    }

    /// A prefix the `PrefixList` names is rendered where it is in scope
    /// and not yet in effect (xml-exc-c14n sec.4); others stay
    /// exclusive.
    #[test]
    fn listed_prefixes_are_rendered_inclusively() {
        let document = parse(
            r#"<n0:o xmlns:n0="urn:zero" xmlns:n1="urn:one" xmlns:n2="urn:two" xmlns="urn:default"><n0:i><n0:j/></n0:i></n0:o>"#,
        );
        let inner = document.root().children().next().expect("child");
        assert_eq!(
            String::from_utf8(inner.canonicalize(&Canonicalization::exclusive(Comments::Omitted)))
                .expect("utf-8"),
            r#"<n0:i xmlns:n0="urn:zero"><n0:j></n0:j></n0:i>"#
        );
        let listed = InclusivePrefixes::parse(" n1\t#default ").expect("a prefix list");
        assert_eq!(
            String::from_utf8(inner.canonicalize(&Canonicalization {
                algorithm: Algorithm::Exclusive(listed),
                comments: Comments::Omitted,
            }))
            .expect("utf-8"),
            r#"<n0:i xmlns="urn:default" xmlns:n0="urn:zero" xmlns:n1="urn:one"><n0:j></n0:j></n0:i>"#
        );
        assert_eq!(InclusivePrefixes::parse("n:1"), None);
        assert_eq!(InclusivePrefixes::parse("#other"), None);
    }

    #[test]
    fn the_node_count_is_bounded() {
        let at_bound = format!("<a>{}</a>", "<b/>".repeat(MAX_NODES - 1));
        assert!(XmlDocument::parse(at_bound.into_bytes()).is_ok());
        let over = format!("<a>{}</a>", "<b/>".repeat(MAX_NODES));
        assert_eq!(
            XmlDocument::parse(over.into_bytes()).err(),
            Some(XmlError::TooManyNodes)
        );
    }

    #[test]
    fn comments_are_kept_only_when_asked() {
        let text = "<r><!--c--><?p d?></r>";
        assert_eq!(
            canonical(text, Comments::Retained),
            "<r><!--c--><?p d?></r>"
        );
        assert_eq!(canonical(text, Comments::Omitted), "<r><?p d?></r>");
    }

    #[test]
    fn descendants_stay_inside_the_subtree() {
        let document = parse("<r><a><b/></a><c/></r>");
        let first = document.root().children().next().expect("a");
        let names: Vec<_> = first
            .descendants()
            .map(|element| element.local_name())
            .collect();
        assert_eq!(names, ["a", "b"]);
    }

    // The examples of W3C Canonical XML 1.0 sec.3 and Canonical XML 1.1
    // sec.3, as far as this reader takes them: it refuses a document
    // type declaration, so each input below is the recommendation's
    // without it, and a value the declaration would have supplied (a
    // default attribute, an attribute type) is left out of the expected
    // form, as the note on each constant says. The examples canonicalise
    // a whole document; here the document element is the apex.

    /// Canonical XML 1.0 sec.3.1, the document element and the
    /// constructs around it; the `DOCTYPE` line is left out.
    const C14N_3_1_INPUT: &str = "<?xml version=\"1.0\"?>\n\n<?xml-stylesheet   href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\n<doc>Hello, world!<!-- Comment 1 --></doc>\n\n<?pi-without-data     ?>\n\n<!-- Comment 2 -->\n\n<!-- Comment 3 -->";

    /// The document element of sec.3.1 in the uncommented canonical
    /// form.
    const C14N_3_1_UNCOMMENTED: &str = "<doc>Hello, world!</doc>";

    /// The document element of sec.3.1 in the commented canonical form.
    const C14N_3_1_COMMENTED: &str = "<doc>Hello, world!<!-- Comment 1 --></doc>";

    /// Canonical XML 1.0 sec.3.2, whose input and canonical form are
    /// identical.
    const C14N_3_2: &str = "<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>";

    /// Canonical XML 1.0 sec.3.3, the input without its `DOCTYPE`.
    const C14N_3_3_INPUT: &str = "<doc>\n   <e1   />\n   <e2   ></e2>\n   <e3   name = \"elem3\"   id=\"elem3\"   />\n   <e4   name=\"elem4\"   id=\"elem4\"   ></e4>\n   <e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I'm\"\n      xmlns:b=\"http://www.ietf.org\"\n      xmlns:a=\"http://www.w3.org\"\n      xmlns=\"http://example.org\"/>\n   <e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n            <e9 xmlns=\"\" xmlns:a=\"http://www.ietf.org\"/>\n         </e8>\n      </e7>\n   </e6>\n</doc>";

    /// The canonical form of sec.3.3, without the `attr="default"` of
    /// `e9` the left-out declaration supplied.
    const C14N_3_3_CANONICAL: &str = "<doc>\n   <e1></e1>\n   <e2></e2>\n   <e3 id=\"elem3\" name=\"elem3\"></e3>\n   <e4 id=\"elem4\" name=\"elem4\"></e4>\n   <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n   <e6 xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\">\n            <e9 xmlns:a=\"http://www.ietf.org\"></e9>\n         </e8>\n      </e7>\n   </e6>\n</doc>";

    /// Canonical XML 1.0 sec.3.4, the input without its `DOCTYPE` and
    /// without `normNames` and `normId`, whose canonical forms depend
    /// on the attribute types the declaration gave them.
    const C14N_3_4_INPUT: &str = "<doc>\n   <text>First line&#x0d;&#10;Second line</text>\n   <value>&#x32;</value>\n   <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n   <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n</doc>";

    /// The canonical form of sec.3.4 for those elements.
    const C14N_3_4_CANONICAL: &str = "<doc>\n   <text>First line&#xD;\nSecond line</text>\n   <value>2</value>\n   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n</doc>";

    /// Canonical XML 1.0 sec.3.6, the input without its ISO-8859-1
    /// declaration, which this reader refuses; the character reference
    /// stands for the same character.
    const C14N_3_6_INPUT: &str = "<doc>&#169;</doc>";

    /// The copyright sign of sec.3.6, which canonicalises to its UTF-8
    /// encoding.
    const COPYRIGHT_SIGN: char = '\u{A9}';

    /// Canonical XML 1.0 sec.3.7, the input without its `DOCTYPE`.
    const C14N_3_7_INPUT: &str = "<doc xmlns=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\">\n   <e1>\n      <e2 xmlns=\"\">\n         <e3 id=\"E3\"/>\n      </e2>\n   </e1>\n</doc>";

    /// The subtree of `e1` from sec.3.7 under inclusive
    /// canonicalisation: the namespaces in scope at the apex rendered on
    /// it, and `xmlns=""` where the default is undeclared below a
    /// rendered one, as the recommendation's subset renders them.
    const C14N_3_7_E1: &str = "<e1 xmlns=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\">\n      <e2 xmlns=\"\">\n         <e3 id=\"E3\"></e3>\n      </e2>\n   </e1>";

    /// Canonical XML 1.1 sec.3.8, the input without its `DOCTYPE`; the
    /// `xml:space="preserve"` the declaration defaulted on `e2` is
    /// written on it.
    const C14N11_3_8_INPUT: &str = "<doc xmlns=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\" xml:base=\"something/else\">\n   <e1>\n      <e2 xmlns=\"\" xml:id=\"abc\" xml:base=\"bar/\" xml:space=\"preserve\">\n         <e3 id=\"E3\" xml:base=\"foo\"/>\n      </e2>\n   </e1>\n</doc>";

    /// The subtree of `e1` from sec.3.8 under Canonical XML 1.1: the
    /// omitted `doc`'s `xml:base` fixed up onto the apex, as in the
    /// recommendation's canonical form.
    const C14N11_3_8_E1: &str = "<e1 xmlns=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\" xml:base=\"something/else\">\n      <e2 xmlns=\"\" xml:base=\"bar/\" xml:id=\"abc\" xml:space=\"preserve\">\n         <e3 id=\"E3\" xml:base=\"foo\"></e3>\n      </e2>\n   </e1>";

    /// `e3` from sec.3.8 as the apex under Canonical XML 1.1: `xml:id`
    /// not inherited, `xml:space` inherited, `xml:base` joined from the
    /// omitted ancestors to the value of the recommendation's canonical
    /// form.
    const C14N11_3_8_E3: &str = "<e3 xmlns:w3c=\"http://www.w3.org\" id=\"E3\" xml:base=\"something/bar/foo\" xml:space=\"preserve\"></e3>";

    /// `e3` from sec.3.8 as the apex under Canonical XML 1.0: every
    /// `xml:` attribute of the nearest ancestor inherited, its own
    /// `xml:base` kept as written.
    const C14N10_3_8_E3: &str = "<e3 xmlns:w3c=\"http://www.w3.org\" id=\"E3\" xml:base=\"foo\" xml:id=\"abc\" xml:space=\"preserve\"></e3>";

    /// `e3` from sec.3.8 under exclusive canonicalisation: no ancestor
    /// context at all.
    const EXCLUSIVE_3_8_E3: &str = "<e3 id=\"E3\" xml:base=\"foo\"></e3>";

    #[test]
    fn the_canonical_xml_examples_canonicalise_as_the_recommendation_shows() {
        for algorithm in [Algorithm::Canonical10, Algorithm::Canonical11] {
            let document = parse(C14N_3_1_INPUT);
            assert_eq!(
                under(document.root(), algorithm.clone(), Comments::Omitted),
                C14N_3_1_UNCOMMENTED
            );
            assert_eq!(
                under(document.root(), algorithm.clone(), Comments::Retained),
                C14N_3_1_COMMENTED
            );
            assert_eq!(
                under(parse(C14N_3_2).root(), algorithm.clone(), Comments::Omitted),
                C14N_3_2
            );
            assert_eq!(
                under(
                    parse(C14N_3_3_INPUT).root(),
                    algorithm.clone(),
                    Comments::Omitted
                ),
                C14N_3_3_CANONICAL
            );
            assert_eq!(
                under(
                    parse(C14N_3_4_INPUT).root(),
                    algorithm.clone(),
                    Comments::Omitted
                ),
                C14N_3_4_CANONICAL
            );
            assert_eq!(
                under(
                    parse(C14N_3_6_INPUT).root(),
                    algorithm.clone(),
                    Comments::Omitted
                ),
                format!("<doc>{COPYRIGHT_SIGN}</doc>")
            );
            let subset = parse(C14N_3_7_INPUT);
            assert_eq!(
                under(named(&subset, "e1"), algorithm, Comments::Omitted),
                C14N_3_7_E1
            );
        }
    }

    #[test]
    fn xml_attributes_are_inherited_as_each_algorithm_says() {
        let document = parse(C14N11_3_8_INPUT);
        assert_eq!(
            under(
                named(&document, "e1"),
                Algorithm::Canonical11,
                Comments::Omitted
            ),
            C14N11_3_8_E1
        );
        assert_eq!(
            under(
                named(&document, "e3"),
                Algorithm::Canonical11,
                Comments::Omitted
            ),
            C14N11_3_8_E3
        );
        assert_eq!(
            under(
                named(&document, "e3"),
                Algorithm::Canonical10,
                Comments::Omitted
            ),
            C14N10_3_8_E3
        );
        assert_eq!(
            under(
                named(&document, "e3"),
                Algorithm::Exclusive(InclusivePrefixes::default()),
                Comments::Omitted
            ),
            EXCLUSIVE_3_8_E3
        );
    }

    /// The `join-URI-References` examples of Canonical XML 1.1 sec.2.4,
    /// and RFC 3986 sec.5.4.1 cases the modification leaves alone.
    #[test]
    fn xml_base_values_join_as_canonical_xml_1_1_says() {
        assert_eq!(join_uri_references("abc/", "../"), "");
        assert_eq!(join_uri_references("../", "../"), "../../");
        assert_eq!(join_uri_references("..", ".."), "../../");
        // The sec.2.4 document with b and c omitted: d's value is
        // joined with theirs, innermost first.
        assert_eq!(
            join_uri_references("..", &join_uri_references("..", "x")),
            "../../x"
        );
        assert_eq!(
            join_uri_references("http://a/b/c/d;p?q", "../g"),
            "http://a/b/g"
        );
        assert_eq!(
            join_uri_references("http://a/b/c/d;p?q", "g?y#s"),
            "http://a/b/c/g?y"
        );
        assert_eq!(join_uri_references("http://a/b/c/d;p?q", "//g"), "http://g");
        assert_eq!(
            join_uri_references("http://a/b/c/d;p?q", "/./g"),
            "http://a/g"
        );
        assert_eq!(join_uri_references("a//b/", "c"), "a/b/c");
        // An empty result renders no xml:base at all.
        let document = parse(r#"<o xml:base="abc/"><i xml:base="../"/></o>"#);
        assert_eq!(
            under(
                named(&document, "i"),
                Algorithm::Canonical11,
                Comments::Omitted
            ),
            "<i></i>"
        );
    }

    /// The rule for a default namespace: rendered at the apex only when
    /// one is in scope, and `xmlns=""` only below a rendered default.
    #[test]
    fn inclusive_canonicalisation_renders_every_namespace_in_scope_at_the_apex() {
        let document = parse(
            r#"<o xmlns:u="urn:unused" xmlns:a="urn:a" xmlns="urn:d"><a:x><a:y/><z xmlns=""/></a:x></o>"#,
        );
        assert_eq!(
            under(
                named(&document, "x"),
                Algorithm::Canonical10,
                Comments::Omitted
            ),
            r#"<a:x xmlns="urn:d" xmlns:a="urn:a" xmlns:u="urn:unused"><a:y></a:y><z xmlns=""></z></a:x>"#
        );
        assert_eq!(
            under(
                named(&document, "z"),
                Algorithm::Canonical10,
                Comments::Omitted
            ),
            r#"<z xmlns:a="urn:a" xmlns:u="urn:unused"></z>"#
        );
    }
}
