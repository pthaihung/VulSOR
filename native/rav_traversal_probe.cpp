#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/DiagnosticOptions.h"
#include "clang/Driver/Compilation.h"
#include "clang/Driver/Driver.h"
#include "clang/Driver/Job.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "clang/Frontend/FrontendActions.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/VirtualFileSystem.h"


class MinimalVisitor final
    : public clang::RecursiveASTVisitor<MinimalVisitor> {
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

        const clang::SourceManager& source_manager =
            context.getSourceManager();

        MinimalVisitor visitor;

        std::cerr << "[probe] visitor created\n";

        std::size_t index = 0;

        for (clang::Decl* decl : translation_unit->decls()) {
            if (decl == nullptr) {
                continue;
            }

            clang::SourceLocation location = decl->getLocation();

            if (location.isInvalid()) {
                location = decl->getBeginLoc();
            }

            if (
                location.isInvalid()
                || !source_manager.isWrittenInMainFile(location)
            ) {
                ++index;
                continue;
            }

            std::cerr << "[probe] before decl "
                    << index
                    << " kind="
                    << decl->getDeclKindName()
                    << '\n';

            const bool success = visitor.TraverseDecl(decl);

            std::cerr << "[probe] after decl "
                    << index
                    << " success="
                    << success
                    << '\n';

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


static std::vector<std::string> collect_driver_arguments(
    int argc,
    const char* const* argv
) {
    std::vector<std::string> arguments;

    arguments.emplace_back(
        "D:/DOWNLOAD/msys64/mingw64/bin/clang.exe"
    );

    bool after_separator = false;

    for (int i = 2; i < argc; ++i) {
        const std::string argument = argv[i];

        if (argument == "--") {
            after_separator = true;
            continue;
        }

        if (after_separator) {
            arguments.push_back(argument);
        }
    }

    arguments.push_back(argv[1]);

    return arguments;
}


int main(int argc, const char* const* argv) {
    std::cerr << "[probe] main\n";

    if (argc < 2) {
        std::cerr
            << "usage: rav_traversal_probe "
            << "<source-file> [-- <clang arguments>]\n";

        return 2;
    }

    clang::DiagnosticOptions diagnostic_options;

    clang::DiagnosticsEngine diagnostics(
        new clang::DiagnosticIDs(),
        diagnostic_options
    );

    const std::vector<std::string> driver_arguments =
        collect_driver_arguments(argc, argv);

    std::vector<const char*> argument_pointers;
    argument_pointers.reserve(driver_arguments.size());

    for (const std::string& argument : driver_arguments) {
        argument_pointers.push_back(argument.c_str());
    }

    std::cerr << "[probe] creating Driver\n";

    clang::driver::Driver driver(
        argument_pointers[0],
        "x86_64-w64-mingw-gnu",
        diagnostics
    );

    driver.setCheckInputsExist(true);

    std::cerr << "[probe] BuildCompilation\n";

    std::unique_ptr<clang::driver::Compilation> compilation(
        driver.BuildCompilation(argument_pointers)
    );

    if (!compilation) {
        std::cerr << "[probe] BuildCompilation failed\n";
        return 1;
    }

    if (compilation->getJobs().empty()) {
        std::cerr << "[probe] no compilation jobs\n";
        return 1;
    }

    const clang::driver::Command* command = nullptr;

    for (const clang::driver::Command& job :
         compilation->getJobs()) {
        command = &job;
        break;
    }

    if (command == nullptr) {
        std::cerr << "[probe] no command\n";
        return 1;
    }

    const llvm::opt::ArgStringList& command_arguments =
        command->getArguments();

    std::cerr << "[probe] creating CompilerInvocation\n";

    clang::CompilerInvocation invocation;

    if (!clang::CompilerInvocation::CreateFromArgs(
            invocation,
            llvm::ArrayRef<const char*>(
                command_arguments.data(),
                command_arguments.size()
            ),
            diagnostics,
            argument_pointers[0])) {
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
