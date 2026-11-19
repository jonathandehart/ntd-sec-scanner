#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include <iostream>

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;

static llvm::cl::OptionCategory ToolCategory("sec-scanner options");

// Matcher: Find calls to unsafe memory/string functions
StatementMatcher UnsafeCallMatcher =
    callExpr(callee(functionDecl(hasAnyName("strcpy", "strcat", "sprintf", "gets"))))
        .bind("unsafeCall");

class UnsafeCallHandler : public MatchFinder::MatchCallback {
public:
  void run(const MatchFinder::MatchResult &Result) override {
    if (const auto *Call = Result.Nodes.getNodeAs<CallExpr>("unsafeCall")) {
      SourceManager &SM = *Result.SourceManager;
      SourceLocation Loc = Call->getBeginLoc();

      // Ignore system headers
      if (SM.isInSystemHeader(Loc)) return;

      unsigned Line = SM.getSpellingLineNumber(Loc);
      unsigned Col = SM.getSpellingColumnNumber(Loc);
      std::string FileName = SM.getFilename(Loc).str();
      std::string CalleeName = Call->getDirectCallee()->getNameAsString();

      std::cout << "[SECURITY WARNING] Unsafe call to '" << CalleeName << "' detected!\n"
                << "  Location: " << FileName << ":" << Line << ":" << Col << "\n"
                << "  Recommendation: Replace with bounded alternative (e.g., snprintf, strlcpy).\n\n";
    }
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

  return Tool.run(newFrontendActionFactory(&Finder).get());
}
