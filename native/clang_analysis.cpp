#include <cstddef>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
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


class IdentityRegistry {
public:
    std::string statement_id(const clang::Stmt* stmt) {
        return get_or_create(
            stmt,
            statement_ids_,
            statement_counter_,
            "stmt:"
        );
    }

    std::string declaration_id(const clang::Decl* decl) {
        return get_or_create(
            decl,
            declaration_ids_,
            declaration_counter_,
            "decl:"
        );
    }

    std::string reference_id(const clang::DeclRefExpr* ref) {
        return get_or_create(
            ref,
            reference_ids_,
            reference_counter_,
            "ref:"
        );
    }

    std::size_t declaration_count() const {
        return declaration_ids_.size();
    }

    std::size_t statement_count() const {
        return statement_ids_.size();
    }

    std::size_t reference_count() const {
        return reference_ids_.size();
    }

private:
    template <typename Node>
    static std::string get_or_create(
        const Node* node,
        std::unordered_map<const Node*, std::string>& ids,
        std::size_t& counter,
        const char* prefix
    ) {
        if (node == nullptr) {
            return {};
        }

        const auto existing = ids.find(node);

        if (existing != ids.end()) {
            return existing->second;
        }

        const std::string id =
            std::string(prefix) + std::to_string(counter++);

        ids.emplace(node, id);

        return id;
    }

    std::unordered_map<const clang::Stmt*, std::string> statement_ids_;
    std::unordered_map<const clang::Decl*, std::string> declaration_ids_;
    std::unordered_map<const clang::DeclRefExpr*, std::string> reference_ids_;

    std::size_t statement_counter_ = 0;
    std::size_t declaration_counter_ = 0;
    std::size_t reference_counter_ = 0;
};


class ASTIdentityVisitor final
    : public clang::RecursiveASTVisitor<ASTIdentityVisitor> {
public:
    explicit ASTIdentityVisitor(IdentityRegistry& registry)
        : registry_(registry) {}

    bool VisitDecl(clang::Decl* decl) {
        if (decl == nullptr) {
            return true;
        }

        registry_.declaration_id(decl);

        return true;
    }

    bool VisitStmt(clang::Stmt* stmt) {
        if (stmt == nullptr) {
            return true;
        }

        registry_.statement_id(stmt);

        return true;
    }

    bool VisitDeclRefExpr(clang::DeclRefExpr* ref) {
        if (ref == nullptr) {
            return true;
        }

        registry_.reference_id(ref);

        const clang::NamedDecl* target = ref->getFoundDecl();

        if (target != nullptr) {
            registry_.declaration_id(target);
        }

        return true;
    }

private:
    IdentityRegistry& registry_;
};

class ASTSmokeConsumer final : public clang::ASTConsumer {
public:
    explicit ASTSmokeConsumer(IdentityRegistry& registry)
        : registry_(registry) {}

    void HandleTranslationUnit(
        clang::ASTContext& context
    ) override {
        std::cerr << "[consumer] HandleTranslationUnit\n";

        clang::TranslationUnitDecl* translation_unit =
            context.getTranslationUnitDecl();

        if (translation_unit == nullptr) {
            failed_ = true;
            return;
        }

        std::cerr << "[consumer] translation unit obtained\n";

        const clang::SourceManager& source_manager =
            context.getSourceManager();

        ASTIdentityVisitor visitor(registry_);

        std::cerr << "[consumer] identity RAV created\n";

        std::size_t user_declarations = 0;

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
                continue;
            }

            ++user_declarations;

            const bool success =
                visitor.TraverseDecl(decl);

            if (!success) {
                failed_ = true;
                return;
            }
        }

        std::cerr
            << "[consumer] user declarations="
            << user_declarations
            << '\n';

        if (registry_.declaration_count() == 0) {
            failed_ = true;
            return;
        }

        if (registry_.statement_count() == 0) {
            failed_ = true;
            return;
        }

        std::cerr
            << "[consumer] declarations="
            << registry_.declaration_count()
            << '\n';

        std::cerr
            << "[consumer] statements="
            << registry_.statement_count()
            << '\n';

        std::cerr
            << "[consumer] references="
            << registry_.reference_count()
            << '\n';
    }

    bool failed() const {
        return failed_;
    }

private:
    IdentityRegistry& registry_;
    bool failed_ = false;
};


class ASTSmokeAction final : public clang::ASTFrontendAction {
public:
    explicit ASTSmokeAction(IdentityRegistry& registry)
        : registry_(registry) {}

    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
        clang::CompilerInstance&,
        llvm::StringRef
    ) override {
        std::cerr << "[action] CreateASTConsumer\n";

        return std::make_unique<ASTSmokeConsumer>(registry_);
    }

private:
    IdentityRegistry& registry_;
};


// ---------------------------------------------------------------------------
// Diagnostic-only lifetime test.
//
// These are intentionally static for this debugging step.
// Do NOT keep this design in the final architecture.
// ---------------------------------------------------------------------------

static std::unique_ptr<clang::driver::Compilation> g_compilation;
static std::unique_ptr<clang::driver::Driver> g_driver;


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


static bool create_compiler_invocation(
    int argc,
    const char* const* argv,
    clang::CompilerInvocation& invocation,
    clang::DiagnosticsEngine& diagnostics
) {
    const std::vector<std::string> driver_arguments =
        collect_driver_arguments(argc, argv);

    std::vector<const char*> argument_pointers;
    argument_pointers.reserve(driver_arguments.size());

    for (const std::string& argument : driver_arguments) {
        argument_pointers.push_back(argument.c_str());
    }

    std::cerr << "[3] creating Clang driver\n";

    g_driver = std::make_unique<clang::driver::Driver>(
        argument_pointers[0],
        "x86_64-w64-mingw-gnu",
        diagnostics
    );

    std::cerr << "[3a] Clang driver created\n";

    g_driver->setCheckInputsExist(true);

    std::cerr << "[3b] driver configured\n";

    g_driver->setCheckInputsExist(true);

    std::cerr << "[3c] driver arguments:\n";

    for (const std::string& argument : driver_arguments) {
        std::cerr << "    [" << argument << "]\n";
    }

    std::cerr << "[3c] testing BuildCompilation with real arguments\n";

    g_compilation.reset(
        g_driver->BuildCompilation(argument_pointers)
    );

    std::cerr << "[3d] minimal BuildCompilation returned\n";

    if (!g_compilation) {
        std::cerr
            << "[3] driver failed to build compilation\n";
        return false;
    }

    std::cerr << "[4] driver compilation created\n";

    if (g_compilation->getJobs().empty()) {
        std::cerr
            << "[4] compilation contains no jobs\n";
        return false;
    }

    const clang::driver::Command* command = nullptr;

    for (const clang::driver::Command& job :
         g_compilation->getJobs()) {
        command = &job;
        break;
    }

    if (command == nullptr) {
        std::cerr
            << "[4] no command job found\n";
        return false;
    }

    std::cerr << "[5] frontend command found\n";

    const llvm::opt::ArgStringList& command_arguments =
        command->getArguments();

    if (command_arguments.empty()) {
        std::cerr
            << "[5] frontend command has no arguments\n";
        return false;
    }

    std::cerr
        << "[6] creating CompilerInvocation\n";

    if (!clang::CompilerInvocation::CreateFromArgs(
            invocation,
            llvm::ArrayRef<const char*>(
                command_arguments.data(),
                command_arguments.size()
            ),
            diagnostics,
            argument_pointers[0])) {
        std::cerr
            << "[6] CompilerInvocation creation failed\n";
        return false;
    }

    std::cerr
        << "[7] CompilerInvocation created\n";

    std::cerr
        << "[7b] about to return from create_compiler_invocation\n";

    return true;
}


int main(int argc, const char* const* argv) {
    std::cerr << "[1] main entered\n";

    if (argc < 2) {
        std::cerr
            << "usage: clang_analysis "
            << "<source-file> [-- <clang arguments>]\n";

        return 2;
    }

    clang::DiagnosticOptions diagnostic_options;

    clang::DiagnosticsEngine diagnostics(
        new clang::DiagnosticIDs(),
        diagnostic_options
    );

    std::cerr
        << "[2] diagnostics object created\n";

    clang::CompilerInvocation invocation;

    if (!create_compiler_invocation(
            argc,
            argv,
            invocation,
            diagnostics)) {
        std::cerr
            << "Failed to create Clang compiler invocation.\n";

        return 1;
    }

    std::cerr
        << "[7a] leaving create_compiler_invocation\n";

    std::cerr << "[8] creating VFS\n";

    auto vfs = clang::createVFSFromCompilerInvocation(
        invocation,
        diagnostics
    );

    if (!vfs) {
        std::cerr
            << "Failed to create Clang virtual file system.\n";

        return 1;
    }

    std::cerr << "[9] VFS created\n";

    clang::CompilerInstance compiler(
        std::make_shared<clang::CompilerInvocation>(
            std::move(invocation)
        )
    );

    std::cerr
        << "[10] CompilerInstance created\n";

    compiler.createDiagnostics(*vfs);

    std::cerr
        << "[11] diagnostics created\n";

    if (!compiler.hasDiagnostics()) {
        std::cerr
            << "Failed to initialize Clang diagnostics.\n";

        return 1;
    }

    IdentityRegistry registry;

    ASTSmokeAction action(registry);

    std::cerr
        << "[12] before ExecuteAction\n";

    const bool success =
        compiler.ExecuteAction(action);

    std::cerr
        << "[13] after ExecuteAction\n";

    if (!success) {
        std::cerr
            << "Clang AST parsing failed.\n";

        return 1;
    }

    std::cout
        << "VulSOR native AST traversal: PASS\n";

    return 0;
}

