#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Lex/Lexer.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/JSON.h"
#include <iostream>

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;

static llvm::cl::OptionCategory ToolCategory("sec-scanner options");

// Matcher: Find calls to unsafe memory/string functions
StatementMatcher UnsafeCallMatcher =
    callExpr(callee(functionDecl(hasAnyName("strcpy", "strcat", "sprintf", "gets"))),
	 hasAncestor (functionDecl().bind("enclosingFunc"))
        ).bind("unsafeCall");

class UnsafeCallHandler : public MatchFinder::MatchCallback {
public:
 
  llvm::json::Array Findings;

  void run(const MatchFinder::MatchResult &Result) override {
    const auto *Call = Result.Nodes.getNodeAs<CallExpr>("unsafeCall");
    const auto *Func = Result.Nodes.getNodeAs<FunctionDecl>("enclosingFunc");
    if (!Call || !Func) return;

    SourceManager &SM = *Result.SourceManager;
    SourceLocation Loc = Call->getBeginLoc();
    if (SM.isInSystemHeader(Loc)) return;

    // NEW: Extract the exact C++ source text of the entire enclosing function
    CharSourceRange FuncRange = CharSourceRange::getTokenRange(Func->getSourceRange());
    llvm::StringRef FuncCode = Lexer::getSourceText(FuncRange, SM, Result.Context->getLangOpts());

    // NEW: Build a structured JSON object for this finding
    llvm::json::Object Finding;
    Finding["rule_id"] = "CWE-120-UNSAFE-STRING";
    Finding["callee"] = Call->getDirectCallee()->getNameAsString();
    Finding["file"] = SM.getFilename(Loc).str();
    Finding["line"] = static_cast<int64_t>(SM.getSpellingLineNumber(Loc));
    Finding["column"] = static_cast<int64_t>(SM.getSpellingColumnNumber(Loc));
    Finding["enclosing_function"] = Func->getNameAsString();
    Finding["function_code"] = FuncCode.str();

    Findings.push_back(std::move(Finding));
  }
};

int main(int argc, const char **argv) {
  auto ExpectedParser = CommonOptionsParser::create(argc, argv, ToolCategory);
  if (!ExpectedParser) {
    llvm::errs() << ExpectedParser.takeError();
    return 1;
  }

  CommonOptionsParser &OptionsParser = ExpectedParser.get();
  ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());

  UnsafeCallHandler Handler;
  MatchFinder Finder;
  Finder.addMatcher(UnsafeCallMatcher, &Handler);

  int Status = Tool.run(newFrontendActionFactory(&Finder).get());

  llvm::outs() << llvm::formatv("{0:2}", llvm::json::Value(std::move(Handler.Findings))) << "\n";

  return Status;
}
