#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecursiveASTVisitor.h>

class MinimalVisitor final
    : public clang::RecursiveASTVisitor<MinimalVisitor> {
};

class TestConsumer final : public clang::ASTConsumer {
public:
    void HandleTranslationUnit(clang::ASTContext& context) override {
        auto* translation_unit = context.getTranslationUnitDecl();

        MinimalVisitor visitor;

        const bool success =
            visitor.TraverseDecl(translation_unit);

        if (!success) {
            __builtin_trap();
        }
    }
};

int main() {
    return 0;
}