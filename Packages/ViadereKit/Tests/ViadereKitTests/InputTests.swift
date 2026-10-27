import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

@Suite("Code entry")
struct CodeEntryTests {
    @Test func formatsWhileTyping() {
        #expect(CodeEntryFormatter.format("").state == .empty)
        #expect(CodeEntryFormatter.format("a").display == "A")
        #expect(CodeEntryFormatter.format("af").display == "AF")
        #expect(CodeEntryFormatter.format("af2").display == "AF-2")
        #expect(CodeEntryFormatter.format("af2345").display == "AF-2345")
        #expect(CodeEntryFormatter.format("af2345").state == .valid)
        #expect(CodeEntryFormatter.format("af23").state == .incomplete(remaining: 2))
    }

    @Test func normalizesLookalikes() {
        // I -> 1 and O -> 0 (but L stays L)
        #expect(CodeEntryFormatter.format("IO3456").canonical == "103456")
        #expect(CodeEntryFormatter.format("io-3456").display == "10-3456")
        #expect(CodeEntryFormatter.format("L03456").canonical == "L03456")
    }

    @Test func ignoresSeparatorsAndCaps() {
        #expect(CodeEntryFormatter.format(" af - 23.45 ").display == "AF-2345")
        #expect(CodeEntryFormatter.format("AF2345999").canonical == "AF2345")
    }

    @Test func rejectsInvalidCharacters() {
        #expect(CodeEntryFormatter.format("af2#45").state == .invalid("#"))
        #expect(CodeEntryFormatter.format("af2é45").canonical == "AF245")
    }

    @Test func matchesCoreNormalization() throws {
        for raw in ["af2345", "AF-2345", "io3456", "1o 3456"] {
            let formatted = CodeEntryFormatter.format(raw)
            #expect(formatted.canonical == (try BusinessCode(raw)).canonical)
        }
    }

    @Test func validResultYieldsCode() {
        #expect(CodeEntryFormatter.format("hb7k29").code?.display == "HB-7K29")
        #expect(CodeEntryFormatter.format("hb7k").code == nil)
    }
}

@Suite("Unified connect input")
struct ConnectInputTests {
    @Test func emptyAndName() {
        #expect(ConnectInputClassifier.evaluate("").kind == .empty)
        let name = ConnectInputClassifier.evaluate("Copperline")
        #expect(name.kind == .name)
        #expect(name.canSubmit)
        #expect(!ConnectInputClassifier.evaluate("C").canSubmit)
    }

    @Test func handles() {
        let partial = ConnectInputClassifier.evaluate("@ha")
        #expect(partial.kind == .handle)
        #expect(partial.validation == .incomplete("Handles have at least 3 characters.") || partial.canSubmit)
        let ok = ConnectInputClassifier.evaluate("@HarborBank")
        #expect(ok.kind == .handle)
        #expect(ok.text == "@harborbank")
        #expect(ok.canSubmit)
        if case .invalid = ConnectInputClassifier.evaluate("@har-bor").validation {} else { Issue.record("expected invalid") }
    }

    @Test func codeModeFormatsAndValidates() {
        let typing = ConnectInputClassifier.evaluate("af23")
        #expect(typing.kind == .code)
        #expect(typing.text == "AF-23")
        #expect(typing.validation == .incomplete("2 more characters"))
        #expect(!typing.canSubmit)
        let done = ConnectInputClassifier.evaluate("af2345")
        #expect(done.kind == .code && done.canSubmit)
        #expect(done.text == "AF-2345")
        #expect(ConnectInputClassifier.evaluate("io3456").text == "10-3456")
    }

    @Test func lettersOnlyStaysNameButOffersCode() {
        let state = ConnectInputClassifier.evaluate("ABCDEF")
        #expect(state.kind == .name)
        #expect(state.alsoCode?.canonical == "ABCDEF")
        #expect(ConnectInputClassifier.evaluate("Costco").alsoCode != nil) // six letters
        #expect(ConnectInputClassifier.evaluate("Costco Wholesale").alsoCode == nil)
    }

    @Test func links() {
        #expect(ConnectInputClassifier.evaluate("https://viadere.com/c/AF2345").canSubmit)
        if case .invalid = ConnectInputClassifier.evaluate("https://evil.example.com/c/AF2345").validation {} else { Issue.record("expected invalid link") }
    }
}

@Suite("Phone and OTP input")
struct PhoneOTPTests {
    @Test func phone() {
        #expect(PhoneInput.normalize("(480) 555-0123")?.e164 == "+14805550123")
        #expect(PhoneInput.normalize("1-480-555-0123")?.e164 == "+14805550123")
        #expect(PhoneInput.normalize("+44 20 7946 0958")?.e164 == "+442079460958")
        #expect(PhoneInput.normalize("555-0123") == nil)
        #expect(PhoneInput.displayFormat("4805550123") == "(480) 555-0123")
        #expect(PhoneInput.displayFormat("48") == "(48")
    }

    @Test func otp() {
        #expect(OTPInput.normalize("12 34-56789") == "123456")
        #expect(OTPInput.isComplete("123456"))
        #expect(!OTPInput.isComplete("12345"))
    }
}
