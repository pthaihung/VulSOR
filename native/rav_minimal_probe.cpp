#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/DiagnosticIDs.h"
#include "clang/Basic/DiagnosticOptions.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Frontend/FrontendOptions.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/VirtualFileSystem.h"


class MinimalVisitor final
    : public clang::RecursiveASTVisitor<MinimalVisitor> {
public:
    bool TraverseDecl(clang::Decl* decl) {
        std::cerr << "[probe] derived TraverseDecl entered\n";

        if (decl == nullptr) {
            std::cerr << "[probe] derived TraverseDecl received null\n";
            return false;
        }

        std::cerr << "[probe] derived TraverseDecl received decl kind="
                  << decl->getDeclKindName()
                  << " ptr="
                  << static_cast<const void*>(decl)
                  << '\n';

        std::cerr << "[probe] before base RecursiveASTVisitor::TraverseDecl\n";

        const bool success =
            clang::RecursiveASTVisitor<MinimalVisitor>::TraverseDecl(decl);

        std::cerr
            << "[probe] after base RecursiveASTVisitor::TraverseDecl "
            << "success="
            << success
            << '\n';

        return success;
    }

    bool TraverseLinkageSpecDecl(clang::LinkageSpecDecl* decl) {
        std::cerr << "[probe] TraverseLinkageSpecDecl entered\n";

        if (decl == nullptr) {
            std::cerr << "[probe] linkage decl is null\n";
            return false;
        }

        std::cerr
            << "[probe] TraverseLinkageSpecDecl received non-null decl\n";

        std::cerr
            << "[probe] before base "
            << "RecursiveASTVisitor::TraverseLinkageSpecDecl\n";

        const bool success =
            clang::RecursiveASTVisitor<MinimalVisitor>::
                TraverseLinkageSpecDecl(decl);

        std::cerr
            << "[probe] after base "
            << "RecursiveASTVisitor::TraverseLinkageSpecDecl "
            << "success="
            << success
            << '\n';

        return success;
    }
};


class TraversalConsumer final : public clang::ASTConsumer {
public:
    void HandleTranslationUnit(clang::ASTContext& context) override {
        std::cerr << "[probe] HandleTranslationUnit\n";

        clang::TranslationUnitDecl* translation_unit =
            context.getTranslationUnitDecl();

        if (translation_unit == nullptr) {
            std::cerr << "[probe] translation unit is null\n";
            return;
        }

        std::cerr << "[probe] translation unit obtained\n";

        MinimalVisitor visitor;

        std::cerr << "[probe] visitor created\n";

        std::size_t index = 0;

        for (clang::Decl* decl : translation_unit->decls()) {
            std::cerr << "[probe] before decl "
                      << index
                      << " kind="
                      << decl->getDeclKindName()
                      << " ptr="
                      << static_cast<const void*>(decl)
                      << " name=";

            if (const auto* named_decl =
                    llvm::dyn_cast<clang::NamedDecl>(decl)) {
                std::cerr << named_decl->getNameAsString();
            } else {
                std::cerr << "<unnamed>";
            }

            std::cerr << '\n';

            if (llvm::isa<clang::LinkageSpecDecl>(decl)) {
                auto* linkage =
                    llvm::cast<clang::LinkageSpecDecl>(decl);

                std::cerr << "[probe] LinkageSpecDecl detected\n";

                std::cerr << "[probe] linkage language="
                          << static_cast<int>(
                                 linkage->getLanguage())
                          << '\n';

                std::cerr
                    << "[probe] before visitor.TraverseDecl(Decl*)\n";

                const bool traversal_success =
                    visitor.TraverseDecl(decl);

                std::cerr
                    << "[probe] after visitor.TraverseDecl(Decl*) "
                    << "success="
                    << traversal_success
                    << '\n';
            } else {
                const bool success =
                    visitor.TraverseDecl(decl);

                std::cerr << "[probe] after decl "
                          << index
                          << " success="
                          << success
                          << '\n';
            }

            ++index;
        }

        std::cerr << "[probe] all declarations traversed\n";
    }
};


class TraversalAction final : public clang::ASTFrontendAction {
protected:
    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
        clang::CompilerInstance&,
        llvm::StringRef
    ) override {
        std::cerr << "[probe] CreateASTConsumer\n";

        return std::make_unique<TraversalConsumer>();
    }
};


static std::vector<const char*> collect_cc1_arguments(
    int argc,
    const char* const* argv
) {
    std::vector<const char*> arguments;

    bool after_separator = false;

    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];

        if (!after_separator) {
            if (argument == "--cc1") {
                after_separator = true;
            }

            continue;
        }

        arguments.push_back(argv[i]);
    }

    return arguments;
}


int main(int argc, const char* const* argv) {
    std::cerr << "[probe] main\n";

    if (argc < 3) {
        std::cerr
            << "usage: rav_minimal_probe "
            << "<ignored-source-name> --cc1 "
            << "<clang-cc1 arguments...>\n";

        return 2;
    }

    const std::vector<const char*> cc1_arguments =
        collect_cc1_arguments(argc, argv);

    if (cc1_arguments.empty()) {
        std::cerr << "[probe] no cc1 arguments\n";
        return 2;
    }

    clang::DiagnosticOptions diagnostic_options;

    clang::DiagnosticsEngine diagnostics(
        new clang::DiagnosticIDs(),
        diagnostic_options
    );

    std::cerr << "[probe] creating CompilerInvocation\n";

    clang::CompilerInvocation invocation;

    if (!clang::CompilerInvocation::CreateFromArgs(
            invocation,
            llvm::ArrayRef<const char*>(
                cc1_arguments.data(),
                cc1_arguments.size()
            ),
            diagnostics,
            argv[0])) {
        std::cerr << "[probe] CompilerInvocation failed\n";
        return 1;
    }

    std::cerr << "[probe] CompilerInvocation created\n";

    auto vfs = clang::createVFSFromCompilerInvocation(
        invocation,
        diagnostics
    );

    if (!vfs) {
        std::cerr << "[probe] VFS creation failed\n";
        return 1;
    }

    std::cerr << "[probe] VFS created\n";

    clang::CompilerInstance compiler(
        std::make_shared<clang::CompilerInvocation>(
            std::move(invocation)
        )
    );

    std::cerr << "[probe] CompilerInstance created\n";

    compiler.createDiagnostics(*vfs);

    if (!compiler.hasDiagnostics()) {
        std::cerr << "[probe] diagnostics failed\n";
        return 1;
    }

    TraversalAction action;

    std::cerr << "[probe] before ExecuteAction\n";

    if (!compiler.ExecuteAction(action)) {
        std::cerr << "[probe] ExecuteAction failed\n";
        return 1;
    }

    std::cerr << "[probe] after ExecuteAction\n";

    return 0;
}