<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class LoginController extends AbstractController
{
    #[Route('/login', name: 'app_login', methods: ['GET', 'POST'])]
    public function index(
        Request $request,
        UserRepository $repository,
        Security $security,
        UserPasswordHasherInterface $passwordHasher,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response
    {
        if ($request->isMethod('POST')) {
            $email = $request->get("email");
            $plainPassword = $request->get("password");

            $token = new CsrfToken('login_form', (string) $request->request->get('_token'));
            if (!$csrfTokenManager->isTokenValid($token)) {
                $this->addFlash('error', 'Invalid CSRF token');
                return $this->render('login/index.html.twig', []);
            }

            try {
                $user = $repository->findOneByEmail((string) $email);

                if (!$user) {
                    $this->addFlash('error', 'Invalid credentials');
                    return $this->render('login/index.html.twig', []);
                }

                $isValid = $passwordHasher->isPasswordValid($user, (string) $plainPassword);

                // Backward compatibility with legacy MD5 hashes: rehash on successful MD5 match
                if (!$isValid && $user->getPassword() === md5((string) $plainPassword)) {
                    $user->setPassword($passwordHasher->hashPassword($user, (string) $plainPassword));
                    $repository->save($user, true);
                    $isValid = true;
                }

                if (!$isValid) {
                    $this->addFlash('error', 'Invalid credentials');
                    return $this->render('login/index.html.twig', []);
                }

                $security->login($user);
                return $this->redirectToRoute('app_blog');

            } catch (\Exception $e) {
                $this->addFlash('error', 'Invalid credentials');
            }
        }

        return $this->render('login/index.html.twig', []);
    }

    #[Route('/logout', name: 'app_logout', methods: ['GET'])]
    public function logout()
    {
        // controller can be blank: it will never be called!
    }

    #[Route('/register', name: 'app_register', methods: ['GET', 'POST'])]
    public function register(
        Request $request,
        UserRepository $userRepository,
        UserPasswordHasherInterface $passwordHasher,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response
    {
        if ($request->isMethod('POST')) {

            $token = new CsrfToken('register_form', (string) $request->request->get('_token'));
            if (!$csrfTokenManager->isTokenValid($token)) {
                $this->addFlash('error', 'Invalid CSRF token');
                return $this->redirectToRoute('app_register');
            }


            $email = $request->get('email');
            $username = $request->get('username');
            $password = $request->get('password');
            $confirmPassword = $request->get('confirmPassword');

            // Check if email is valid and not already in use
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $this->addFlash('error', 'Email is not valid');
                return $this->redirectToRoute('app_register');
            }

            // Check if email is not already in use
            $user = $userRepository->findOneBy(['email' => $email]);
            if ($user) {
                $this->addFlash('error', 'Email is already in use');
                return $this->redirectToRoute('app_register');
            }

            // Check if username is not already in use
            $user = $userRepository->findOneBy(['username' => $username]);
            if ($user) {
                $this->addFlash('error', 'Username is already in use');
                return $this->redirectToRoute('app_register');
            }

            // Check if password is not empty
            if (empty($password)) {
                $this->addFlash('error', 'Password cannot be empty');
                return $this->redirectToRoute('app_register');
            }

            // Check if password and confirm password are the same
            if ($password !== $confirmPassword) {
                $this->addFlash('error', 'Password and confirm password are not the same');
                return $this->redirectToRoute('app_register');
            }

            // Create the new user
            $user = new User();
            $user->setEmail($email);
            $user->setRoles(['ROLE_USER']);
            $user->setUsername($username);
            $hashed = $passwordHasher->hashPassword($user, (string) $password);
            $user->setPassword($hashed);

            $userRepository->save($user, true);

            return $this->redirectToRoute('app_login', [
                'message' => 'User created successfully, please log in'
            ]);
        }

        return $this->render('login/register.html.twig', []);
    }

}
